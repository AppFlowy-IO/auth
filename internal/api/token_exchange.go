package api

import (
	"context"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/didip/tollbooth/v5"
	"github.com/didip/tollbooth/v5/limiter"
	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/oauthserver"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

const (
	tokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange"
	accessTokenType    = "urn:ietf:params:oauth:token-type:access_token"
)

type tokenExchange struct {
	entra    *provider.EntraAccessTokens
	limiter  *limiter.Limiter
	inFlight chan struct{}
}

func newTokenExchange(c *conf.TokenExchangeConfiguration) *tokenExchange {
	return &tokenExchange{
		entra:    provider.NewEntraAccessTokens(c.TenantID, &http.Client{Timeout: 5 * time.Second}),
		limiter:  newLimiterPer5mOver1h(float64(c.RateLimit)),
		inFlight: make(chan struct{}, c.MaxConcurrent),
	}
}

func (a *API) exchangeJWKS(w http.ResponseWriter, _ *http.Request) error {
	keys := a.config.TokenExchange.SigningKeys.JwtKeysDecoder
	response := JwksResponse{Keys: make([]jwk.Key, 0, len(keys))}
	for _, key := range keys {
		response.Keys = append(response.Keys, key.PublicKey)
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	return sendJSON(w, http.StatusOK, response)
}

// Accept a single target and access-token subject. Credentials and assertions
// stay in the header/body; the grant name may also use GoTrue's usual query syntax.
func exchangeForm(r *http.Request) (url.Values, error) {
	bad := apierrors.NewOAuthError("invalid_request", "Expected a form-encoded access-token exchange")
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return nil, bad
	}
	if err := r.ParseForm(); err != nil {
		return nil, bad
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) > 1 || (len(query) == 1 && len(query["grant_type"]) != 1) {
		return nil, bad
	}
	for name, values := range r.Form {
		if len(values) != 1 || values[0] == "" {
			return nil, bad
		}
		switch name {
		case "grant_type", "subject_token_type", "subject_token", "requested_token_type", "audience", "scope":
		case "resource":
			return nil, apierrors.NewOAuthError("invalid_target", "Use the configured audience")
		default:
			return nil, bad
		}
	}
	form := r.PostForm
	if form.Get("subject_token_type") != accessTokenType || form.Get("subject_token") == "" || len(form.Get("subject_token")) > 32*1024 {
		return nil, bad
	}
	if t := form.Get("requested_token_type"); t != "" && t != accessTokenType {
		return nil, bad
	}
	return form, nil
}

func exchangeScopes(request string, allowed, delegated []string) (string, error) {
	scopes := make([]string, 0, len(allowed))
	for _, scope := range allowed {
		if slices.Contains(delegated, scope) && !slices.Contains(scopes, scope) {
			scopes = append(scopes, scope)
		}
	}
	if request != "" {
		requested := strings.Fields(request)
		if !models.HasAllScopes(scopes, requested) {
			return "", apierrors.NewOAuthError("invalid_scope", "Scope exceeds delegation")
		}
		scopes = requested
	}
	if len(scopes) == 0 {
		return "", apierrors.NewOAuthError("invalid_scope", "No authorized scope")
	}
	slices.Sort(scopes)
	return strings.Join(slices.Compact(scopes), " "), nil
}

func exchangeClientError(w http.ResponseWriter) error {
	w.Header().Set("WWW-Authenticate", `Basic realm="token-exchange"`)
	return sendJSON(w, http.StatusUnauthorized, apierrors.NewOAuthError("invalid_client", "Client authentication failed"))
}

func (a *API) exchangeAccessToken(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	form, err := exchangeForm(r)
	if err != nil {
		return err
	}
	id, secret, basic := r.BasicAuth()
	registration, allowed := a.config.TokenExchange.Clients[id]
	if !basic || !allowed || secret == "" {
		return exchangeClientError(w)
	}
	select {
	case a.exchange.inFlight <- struct{}{}:
		defer func() { <-a.exchange.inFlight }()
	default:
		return apierrors.NewTooManyRequestsError(apierrors.ErrorCodeOverRequestRateLimit, "Token exchange is busy")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	db := a.db.WithContext(ctx)
	client, err := models.FindOAuthServerClientByID(db, uuid.FromStringOrNil(id))
	if err != nil {
		if models.IsNotFoundError(err) {
			return exchangeClientError(w)
		}
		return err
	}
	if !client.IsConfidential() || oauthserver.ValidateClientAuthMethod(client, models.TokenEndpointAuthMethodClientSecretBasic) != nil ||
		oauthserver.ValidateClientAuthentication(client, secret) != nil {
		return exchangeClientError(w)
	}
	if tollbooth.LimitByKeys(a.exchange.limiter, []string{id}) != nil {
		return apierrors.NewTooManyRequestsError(apierrors.ErrorCodeOverRequestRateLimit, "Token exchange rate limit reached")
	}
	if target := form.Get("audience"); target != "" && target != registration.Audience {
		return apierrors.NewOAuthError("invalid_target", "Unregistered audience")
	}
	subject, err := a.exchange.entra.Verify(ctx, form.Get("subject_token"), registration.Audience, registration.EntraClientID, a.Now())
	if err != nil {
		if errors.Is(err, provider.ErrEntraKeysUnavailable) {
			w.Header().Set("Retry-After", "5")
			return sendJSON(w, http.StatusServiceUnavailable, apierrors.NewOAuthError("temporarily_unavailable", "Unable to retrieve Entra signing keys"))
		}
		return apierrors.NewOAuthError("invalid_grant", "Invalid Entra delegation")
	}
	scope, err := exchangeScopes(form.Get("scope"), registration.Scopes, subject.Scopes)
	if err != nil {
		return err
	}
	var response *exchangeResponse
	err = db.Transaction(func(tx *storage.Connection) error {
		user, err := a.exchangeUser(tx, subject.ObjectID, client)
		if err != nil {
			return err
		}
		response, err = a.issueExchangeToken(r.WithContext(ctx), tx, user, client.ID, registration.Audience, scope, subject.Expiry)
		return err
	})
	if err != nil {
		return err
	}
	return sendJSON(w, http.StatusOK, response)
}

// The OIDC sign-in stores verified Entra claims in identities.identity_data.
// A dashboard's pairwise sub or an email match cannot establish this binding.
// Recheck the authenticated client after the remote key lookup. Serialize grants
// for this user so retries share one live session for the same client and scope.
func (a *API) exchangeUser(tx *storage.Connection, oid string, client *models.OAuthServerClient) (*models.User, error) {
	invalid := apierrors.NewOAuthError("invalid_grant", "No active linked identity")
	if !a.config.CustomOAuth.Enabled {
		return nil, invalid
	}
	var matches []models.Identity
	err := tx.RawQuery(`SELECT i.user_id FROM identities i
		JOIN users u ON u.id = i.user_id
		JOIN custom_oauth_providers p ON p.identifier = i.provider
		JOIN oauth_clients c ON c.id = ? AND c.deleted_at IS NULL AND c.client_secret_hash = ?
		  AND c.client_type = ? AND c.token_endpoint_auth_method = ?
		WHERE p.identifier = ? AND p.enabled AND p.provider_type = 'oidc' AND p.issuer = ?
		  AND u.is_super_admin IS NOT TRUE
		  AND i.identity_data->>'iss' = p.issuer
		  AND i.identity_data#>>'{custom_claims,tid}' = ?
		  AND i.identity_data#>>'{custom_claims,oid}' = ?
		LIMIT 2 FOR NO KEY UPDATE OF u FOR SHARE OF i, p, c`, client.ID, client.ClientSecretHash,
		client.ClientType, client.TokenEndpointAuthMethod, a.config.TokenExchange.Provider, a.exchange.entra.Issuer(),
		a.config.TokenExchange.TenantID, oid).All(&matches)
	if err != nil {
		return nil, err
	}
	if len(matches) != 1 {
		return nil, invalid
	}
	user, err := models.FindUserByID(tx, matches[0].UserID)
	if err != nil {
		return nil, err
	}
	if user.IsAnonymous || user.DeletedAt != nil || user.IsBanned() || !user.IsConfirmed() || slices.Contains(a.config.JWT.AdminRoles, user.Role) {
		return nil, invalid
	}
	return user, nil
}

type exchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope"`
}

func (a *API) issueExchangeToken(r *http.Request, tx *storage.Connection, user *models.User, client uuid.UUID, audience, scope string, sourceExpiry time.Time) (*exchangeResponse, error) {
	now := a.Now()
	lifetime := min(5*time.Minute, time.Duration(a.config.JWT.Exp)*time.Second)
	if limit := a.config.Sessions.Timebox; limit != nil && *limit > 0 {
		lifetime = min(lifetime, *limit)
	}
	expiry := time.Unix(min(now.Add(lifetime).Unix(), sourceExpiry.Unix()), 0).UTC()
	if !expiry.After(now) {
		return nil, apierrors.NewOAuthError("invalid_grant", "Delegation expired")
	}
	session, err := models.GrantExchangeSession(tx, user.ID, client, scope, now, expiry, a.config.Sessions.Timebox)
	if err != nil {
		return nil, err
	}
	if session.NotAfter.Before(expiry) {
		expiry = *session.NotAfter
	}
	// A distinct signing key and access-token profile keep older services from
	// mistaking delegated data access for a full interactive GoTrue login.
	key, err := conf.GetSigningJwk(&conf.JWTConfiguration{Keys: a.config.TokenExchange.SigningKeys.JwtKeysDecoder})
	if err != nil {
		return nil, err
	}
	private, err := conf.GetSigningKey(key)
	if err != nil {
		return nil, err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": strings.TrimRight(a.config.API.ExternalURL, "/"), "sub": user.ID.String(),
		"aud": audience, "exp": expiry.Unix(), "iat": now.Unix(), "jti": uuid.Must(uuid.NewV4()).String(),
		"session_id": session.ID.String(), "client_id": client.String(), "scope": scope,
	})
	token.Header["kid"], token.Header["typ"] = key.KeyID(), "at+jwt"
	encoded, err := token.SignedString(private)
	if err != nil {
		return nil, err
	}
	if err := models.NewAuditLogEntry(a.config.AuditLog, r, tx, user, models.LoginAction, "", map[string]interface{}{
		"method": "token_exchange", "client_id": client.String(), "audience": audience, "scope": scope,
	}); err != nil {
		return nil, err
	}
	remaining := expiry.Unix() - a.Now().Unix()
	if remaining <= 0 {
		return nil, apierrors.NewOAuthError("invalid_grant", "Delegation expired")
	}
	return &exchangeResponse{AccessToken: encoded, TokenType: "Bearer", IssuedTokenType: accessTokenType, ExpiresIn: remaining, Scope: scope}, nil
}
