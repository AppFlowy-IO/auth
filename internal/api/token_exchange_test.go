package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
)

type exchangeTransport func(*http.Request) (*http.Response, error)

func (f exchangeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type exchangeFixture struct {
	api, legacy                                   *API
	client, oid, tenant, caller, audience, secret string
	entra                                         *rsa.PrivateKey
	public                                        *ecdsa.PublicKey
	user                                          *models.User
	login                                         *models.RefreshToken
}

func (f *exchangeFixture) registerClient(t *testing.T) {
	t.Helper()
	hash := sha256.Sum256([]byte(f.secret))
	client := &models.OAuthServerClient{
		ID: uuid.FromStringOrNil(f.client), RegistrationType: "manual",
		ClientType: models.OAuthServerClientTypeConfidential, TokenEndpointAuthMethod: models.TokenEndpointAuthMethodClientSecretBasic,
		ClientSecretHash: base64.RawURLEncoding.EncodeToString(hash[:]), GrantTypes: "authorization_code",
		RedirectURIs: "https://dashboard.example/callback",
	}
	require.NoError(t, models.CreateOAuthServerClient(f.legacy.db, client))
}

func newExchangeFixture(t *testing.T) *exchangeFixture {
	t.Helper()
	legacy, cfg, err := setupAPIForTest()
	require.NoError(t, err)
	t.Cleanup(func() { legacy.db.Close() })
	id := func() string { return uuid.Must(uuid.NewV4()).String() }
	f := &exchangeFixture{legacy: legacy, client: id(), oid: id(), tenant: id(), caller: id(), audience: id(), secret: id()}
	cfg.Sessions.SinglePerUser = true
	cfg.Hook.CustomAccessToken.Enabled = false
	f.user, err = models.NewUser("", id()+"@example.com", "test-password", cfg.JWT.Aud, nil)
	require.NoError(t, err)
	confirmed := time.Now()
	f.user.EmailConfirmedAt = &confirmed
	require.NoError(t, legacy.db.Create(f.user))
	f.login, err = models.GrantAuthenticatedUser(legacy.db, f.user, models.GrantParams{})
	require.NoError(t, err)
	f.registerClient(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	f.public = &key.PublicKey
	signing, err := jwk.FromRaw(key)
	require.NoError(t, err)
	require.NoError(t, signing.Set("kid", "data-key"))
	require.NoError(t, signing.Set("alg", "ES256"))
	require.NoError(t, signing.Set("key_ops", jwk.KeyOperationList{jwk.KeyOpSign}))
	keys, err := json.Marshal([]jwk.Key{signing})
	require.NoError(t, err)
	cfg.TokenExchange = conf.TokenExchangeConfiguration{
		Enabled: true, TenantID: f.tenant, Provider: "custom:" + id(), RateLimit: 150, MaxConcurrent: 8,
		Clients: conf.ExchangeClients{f.client: {EntraClientID: f.caller, Audience: f.audience, Scopes: []string{"data.read", "data.write"}}},
	}
	require.NoError(t, cfg.TokenExchange.SigningKeys.Decode(string(keys)))
	require.NoError(t, cfg.Validate())
	f.api = NewAPI(cfg, legacy.db)
	f.entra, err = rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub, err := jwk.FromRaw(&f.entra.PublicKey)
	require.NoError(t, err)
	require.NoError(t, pub.Set("kid", "upstream-key"))
	jwks, err := json.Marshal(JwksResponse{Keys: []jwk.Key{pub}})
	require.NoError(t, err)
	f.api.exchange.entra = provider.NewEntraAccessTokens(f.tenant, &http.Client{Transport: exchangeTransport(func(r *http.Request) (*http.Response, error) {
		require.Equal(t, "https://login.microsoftonline.com/"+f.tenant+"/discovery/v2.0/keys", r.URL.String())
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(jwks)))}, nil
	})})
	issuer := f.api.exchange.entra.Issuer()
	connection := &models.CustomOAuthProvider{
		ProviderType: models.ProviderTypeOIDC, Identifier: cfg.TokenExchange.Provider, ClientID: id(),
		Name: "Exchange fixture", ClientSecret: "fixture", Issuer: &issuer, Enabled: true,
	}
	require.NoError(t, models.CreateCustomOAuthProvider(legacy.db, connection))
	identity, err := models.NewIdentity(f.user, connection.Identifier, map[string]interface{}{
		"sub": "pairwise-login-subject", "iss": issuer, "custom_claims": map[string]interface{}{"tid": f.tenant, "oid": f.oid},
	})
	require.NoError(t, err)
	require.NoError(t, legacy.db.Create(identity))
	return f
}

func (f *exchangeFixture) subject(t *testing.T, changes jwt.MapClaims) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": f.api.exchange.entra.Issuer(), "aud": f.audience, "sub": "different-pairwise-api-subject",
		"tid": f.tenant, "oid": f.oid, "azp": f.caller, "ver": "2.0", "scp": "data.read unrelated",
		"exp": now.Add(90 * time.Second).Unix(), "nbf": now.Add(-time.Minute).Unix(), "iat": now.Unix(),
	}
	for k, v := range changes {
		claims[k] = v
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "upstream-key"
	raw, err := token.SignedString(f.entra)
	require.NoError(t, err)
	return raw
}

func (f *exchangeFixture) exchange(t *testing.T, api *API, raw, secret string, extra url.Values) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"grant_type": {tokenExchangeGrant}, "subject_token_type": {accessTokenType}, "subject_token": {raw}}
	for k, v := range extra {
		form[k] = v
	}
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r.SetBasicAuth(f.client, secret)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	api.handler.ServeHTTP(w, r)
	return w
}

func TestTokenExchangeSession(t *testing.T) {
	f := newExchangeFixture(t)
	raw := f.subject(t, nil)
	disabled := f.exchange(t, f.legacy, raw, f.secret, nil)
	require.Equal(t, 400, disabled.Code)
	require.Contains(t, disabled.Body.String(), "unsupported_grant_type")
	w := f.exchange(t, f.api, raw, f.secret, nil)
	require.Equal(t, 200, w.Code, w.Body.String())
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	require.Equal(t, accessTokenType, result["issued_token_type"])
	require.Equal(t, "data.read", result["scope"])
	require.NotContains(t, result, "refresh_token")
	require.LessOrEqual(t, result["expires_in"].(float64), float64(90))
	token, err := jwt.Parse(result["access_token"].(string), func(token *jwt.Token) (interface{}, error) { return f.public, nil },
		jwt.WithValidMethods([]string{"ES256"}), jwt.WithAudience(f.audience), jwt.WithIssuer(f.api.config.API.ExternalURL))
	require.NoError(t, err)
	require.Equal(t, "at+jwt", token.Header["typ"])
	claims := token.Claims.(jwt.MapClaims)
	require.Equal(t, f.user.ID.String(), claims["sub"])
	require.Equal(t, f.client, claims["client_id"])
	require.Equal(t, "data.read", claims["scope"])
	sid := uuid.FromStringOrNil(claims["session_id"].(string))
	session, err := models.FindSessionByID(f.api.db, sid, false)
	require.NoError(t, err)
	require.Equal(t, f.user.ID, session.UserID)
	require.Equal(t, int64(claims["exp"].(float64)), session.NotAfter.Unix())
	require.Nil(t, session.RefreshTokenHmacKey)
	_, err = models.FindTokenBySessionID(f.api.db, &sid)
	require.True(t, models.IsNotFoundError(err))

	// Concurrent renewals retain a revocable session and independently signed tokens.
	const renewals = 4
	responses := make(chan *httptest.ResponseRecorder, renewals)
	for range renewals {
		go func() { responses <- f.exchange(t, f.api, raw, f.secret, nil) }()
	}
	seen := map[string]bool{claims["jti"].(string): true}
	for range renewals {
		next := <-responses
		require.Equal(t, 200, next.Code, next.Body.String())
		var renewed exchangeResponse
		require.NoError(t, json.Unmarshal(next.Body.Bytes(), &renewed))
		checked, err := jwt.Parse(renewed.AccessToken, func(*jwt.Token) (interface{}, error) { return f.public, nil })
		require.NoError(t, err)
		newClaims := checked.Claims.(jwt.MapClaims)
		require.Equal(t, sid.String(), newClaims["session_id"])
		jti := newClaims["jti"].(string)
		require.False(t, seen[jti])
		seen[jti] = true
	}
	userReq := httptest.NewRequest(http.MethodGet, "/user", nil)
	userReq.Header.Set("Authorization", "Bearer "+result["access_token"].(string))
	userResponse := httptest.NewRecorder()
	f.api.handler.ServeHTTP(userResponse, userReq)
	require.NotEqual(t, 200, userResponse.Code)
	for _, path := range []string{"/.well-known/jwks.json", "/.well-known/token-exchange-jwks.json"} {
		pub := httptest.NewRecorder()
		f.api.handler.ServeHTTP(pub, httptest.NewRequest(http.MethodGet, path, nil))
		require.Equal(t, 200, pub.Code)
		require.NotContains(t, pub.Body.String(), `"d":`)
		require.Equal(t, strings.Contains(path, "token-exchange"), strings.Contains(pub.Body.String(), "data-key"))
	}
	// A grant created after the interactive login cannot displace it under single-session policy.
	refresh := httptest.NewRequest(http.MethodPost, "/token?grant_type=refresh_token", strings.NewReader(`{"refresh_token":"`+f.login.Token+`"}`))
	refresh.Header.Set("Content-Type", "application/json")
	refreshed := httptest.NewRecorder()
	f.api.handler.ServeHTTP(refreshed, refresh)
	require.Equal(t, 200, refreshed.Code, refreshed.Body.String())
	require.NoError(t, models.LogoutSession(f.api.db, sid))
	_, err = models.FindSessionByID(f.api.db, sid, false)
	require.True(t, models.IsNotFoundError(err))
	afterLogout := f.exchange(t, f.api, raw, f.secret, nil)
	require.Equal(t, 200, afterLogout.Code, afterLogout.Body.String())
	var again exchangeResponse
	require.NoError(t, json.Unmarshal(afterLogout.Body.Bytes(), &again))
	checked, err := jwt.Parse(again.AccessToken, func(*jwt.Token) (interface{}, error) { return f.public, nil })
	require.NoError(t, err)
	require.NotEqual(t, sid.String(), checked.Claims.(jwt.MapClaims)["session_id"])
}

func TestTokenExchangeMultipleBackends(t *testing.T) {
	first := newExchangeFixture(t)
	second := *first
	id := func() string { return uuid.Must(uuid.NewV4()).String() }
	second.client, second.secret, second.caller, second.audience = id(), id(), id(), id()
	second.registerClient(t)
	second.api.config.TokenExchange.Clients[second.client] = conf.ExchangeClient{
		EntraClientID: second.caller, Audience: second.audience, Scopes: []string{"reports.read"},
	}
	firstToken := first.subject(t, nil)
	secondToken := second.subject(t, jwt.MapClaims{"scp": "reports.read"})
	for _, tc := range []struct {
		client       *exchangeFixture
		own, foreign string
	}{
		{first, firstToken, secondToken}, {&second, secondToken, firstToken},
	} {
		w := tc.client.exchange(t, tc.client.api, tc.own, tc.client.secret, nil)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var response exchangeResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		parsed, err := jwt.Parse(response.AccessToken, func(*jwt.Token) (interface{}, error) { return tc.client.public, nil }, jwt.WithAudience(tc.client.audience))
		require.NoError(t, err)
		claims := parsed.Claims.(jwt.MapClaims)
		require.Equal(t, first.user.ID.String(), claims["sub"])
		require.Equal(t, tc.client.client, claims["client_id"])
		w = tc.client.exchange(t, tc.client.api, tc.foreign, tc.client.secret, nil)
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "invalid_grant")
	}
}

func TestTokenExchangeScopeAndLifetime(t *testing.T) {
	f := newExchangeFixture(t)
	now := time.Now().Truncate(time.Second)
	f.api.overrideTime = func() time.Time { return now }
	both := jwt.MapClaims{"scp": "data.write data.read", "exp": now.Add(time.Hour).Unix()}
	read := url.Values{"scope": {"data.read"}, "audience": {f.audience}}
	redeem := func(claims jwt.MapClaims, fields url.Values) (exchangeResponse, jwt.MapClaims) {
		t.Helper()
		w := f.exchange(t, f.api, f.subject(t, claims), f.secret, fields)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var result exchangeResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		parsed, err := jwt.Parse(result.AccessToken, func(*jwt.Token) (interface{}, error) { return f.public, nil })
		require.NoError(t, err)
		return result, parsed.Claims.(jwt.MapClaims)
	}
	response, first := redeem(both, read)
	require.Equal(t, "data.read", response.Scope)
	require.Equal(t, int64(300), response.ExpiresIn)
	_, all := redeem(both, nil)
	require.Equal(t, "data.read data.write", all["scope"])
	require.NotEqual(t, first["session_id"], all["session_id"])

	// Reusing a live session must not extend a new token beyond its own evidence.
	both["exp"] = now.Add(30 * time.Second).Unix()
	response, shorter := redeem(both, read)
	require.Equal(t, first["session_id"], shorter["session_id"])
	require.Equal(t, int64(30), response.ExpiresIn)
	limit := 10 * time.Second
	f.api.config.Sessions.Timebox = &limit
	response, _ = redeem(both, read)
	require.LessOrEqual(t, response.ExpiresIn, int64(10))
}

func TestTokenExchangeBoundaries(t *testing.T) {
	f := newExchangeFixture(t)
	for _, tc := range []struct {
		name   string
		claims jwt.MapClaims
		form   url.Values
		code   string
	}{
		{"foreign issuer", jwt.MapClaims{"iss": "https://example.com"}, nil, "invalid_grant"},
		{"tenant", jwt.MapClaims{"tid": uuid.Nil.String()}, nil, "invalid_grant"},
		{"audience", jwt.MapClaims{"aud": f.caller}, nil, "invalid_grant"},
		{"multiple audiences", jwt.MapClaims{"aud": []string{f.audience, f.caller}}, nil, "invalid_grant"},
		{"caller", jwt.MapClaims{"azp": f.audience}, nil, "invalid_grant"},
		{"v1 token", jwt.MapClaims{"ver": "1.0"}, nil, "invalid_grant"},
		{"app only", jwt.MapClaims{"idtyp": "app"}, nil, "invalid_grant"},
		{"no delegated scopes", jwt.MapClaims{"scp": ""}, nil, "invalid_grant"},
		{"unlinked subject", jwt.MapClaims{"oid": uuid.Must(uuid.NewV4()).String(), "email": f.user.GetEmail()}, nil, "invalid_grant"},
		{"expired", jwt.MapClaims{"exp": time.Now().Add(-time.Minute).Unix()}, nil, "invalid_grant"},
		{"future", jwt.MapClaims{"nbf": time.Now().Add(time.Minute).Unix()}, nil, "invalid_grant"},
		{"ungranted scope", nil, url.Values{"scope": {"data.write"}}, "invalid_scope"},
		{"unregistered target", nil, url.Values{"audience": {"another-api"}}, "invalid_target"},
		{"ID token type", nil, url.Values{"subject_token_type": {"urn:ietf:params:oauth:token-type:id_token"}}, "invalid_request"},
		{"ambiguous scope", nil, url.Values{"scope": {"data.read", "data.write"}}, "invalid_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := f.exchange(t, f.api, f.subject(t, tc.claims), f.secret, tc.form)
			require.Equal(t, 400, w.Code, w.Body.String())
			var response map[string]string
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
			require.Equal(t, tc.code, response["error"])
		})
	}
	w := f.exchange(t, f.api, f.subject(t, nil), "wrong", nil)
	require.Equal(t, 401, w.Code)
	require.Contains(t, w.Header().Get("WWW-Authenticate"), "Basic")
	trusted := f.entra
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	f.entra = other
	foreign := f.subject(t, nil)
	f.entra = trusted
	w = f.exchange(t, f.api, foreign, f.secret, nil)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "invalid_grant")
	require.NoError(t, f.api.db.RawQuery("UPDATE users SET banned_until = now() + interval '10 minutes' WHERE id = ?", f.user.ID).Exec())
	w = f.exchange(t, f.api, f.subject(t, nil), f.secret, nil)
	require.Equal(t, 400, w.Code)
	require.Contains(t, w.Body.String(), "invalid_grant")
	require.NoError(t, f.api.db.RawQuery("UPDATE users SET banned_until = NULL WHERE id = ?", f.user.ID).Exec())
	require.NoError(t, f.api.db.RawQuery("UPDATE custom_oauth_providers SET enabled = false WHERE identifier = ?", f.api.config.TokenExchange.Provider).Exec())
	w = f.exchange(t, f.api, f.subject(t, nil), f.secret, nil)
	require.Equal(t, 400, w.Code)
	require.Contains(t, w.Body.String(), "invalid_grant")
}

func TestTokenExchangeRefusesAmbiguousLinksAndPublicClients(t *testing.T) {
	f := newExchangeFixture(t)
	second, err := models.NewUser("", uuid.Must(uuid.NewV4()).String()+"@example.com", "test-password", f.api.config.JWT.Aud, nil)
	require.NoError(t, err)
	second.EmailConfirmedAt = f.user.EmailConfirmedAt
	require.NoError(t, f.api.db.Create(second))
	identity, err := models.NewIdentity(second, f.api.config.TokenExchange.Provider, map[string]interface{}{
		"sub": "different-login-subject", "iss": f.api.exchange.entra.Issuer(), "custom_claims": map[string]interface{}{"tid": f.tenant, "oid": f.oid},
	})
	require.NoError(t, err)
	require.NoError(t, f.api.db.Create(identity))
	raw := f.subject(t, nil)
	w := f.exchange(t, f.api, raw, f.secret, nil)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "invalid_grant")
	require.NoError(t, f.api.db.RawQuery("UPDATE oauth_clients SET client_type = 'public', token_endpoint_auth_method = 'none' WHERE id = ?", f.client).Exec())
	w = f.exchange(t, f.api, raw, f.secret, nil)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, w.Body.String(), "invalid_client")
}

func TestTokenExchangeIsolationDuringKeyOutage(t *testing.T) {
	f := newExchangeFixture(t)
	release := make(chan struct{})
	var unblock sync.Once
	finish := func() { unblock.Do(func() { close(release) }) }
	f.api.exchange.entra = provider.NewEntraAccessTokens(f.tenant, &http.Client{Transport: exchangeTransport(func(r *http.Request) (*http.Response, error) {
		<-release
		return &http.Response{StatusCode: 503, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})})
	raw := f.subject(t, nil)
	capacity := cap(f.api.exchange.inFlight)
	results := make(chan *httptest.ResponseRecorder, capacity)
	var requests sync.WaitGroup
	defer func() { finish(); requests.Wait() }()
	for range capacity {
		requests.Add(1)
		go func() {
			defer requests.Done()
			results <- f.exchange(t, f.api, raw, f.secret, nil)
		}()
	}
	require.Eventually(t, func() bool { return len(f.api.exchange.inFlight) == capacity }, 3*time.Second, 5*time.Millisecond)
	throttled := f.exchange(t, f.api, raw, f.secret, nil)
	require.Equal(t, http.StatusTooManyRequests, throttled.Code)
	// These complete while every exchange slot is still occupied.
	for _, tc := range []struct{ grant, body string }{
		{"refresh_token", `{"refresh_token":"` + f.login.Token + `"}`},
		{"password", `{"email":"` + f.user.GetEmail() + `","password":"test-password"}`},
	} {
		req := httptest.NewRequest(http.MethodPost, "/token?grant_type="+tc.grant, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.api.handler.ServeHTTP(w, req)
		require.Equal(t, 200, w.Code, w.Body.String())
	}
	finish()
	for range capacity {
		w := <-results
		require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
		require.Contains(t, w.Body.String(), "temporarily_unavailable")
	}
}

func TestTokenExchangeAdministersClientsWithoutTheOAuthServer(t *testing.T) {
	f := newExchangeFixture(t)
	require.False(t, f.api.config.OAuthServer.Enabled)
	admin, err := jwt.NewWithClaims(jwt.SigningMethodHS256, &AccessTokenClaims{Role: "supabase_admin"}).SignedString([]byte(f.api.config.JWT.Secret))
	require.NoError(t, err)
	register := func(api *API) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/admin/oauth/clients", strings.NewReader(
			`{"client_name":"Dashboard","redirect_uris":["https://dashboard.example/callback"],"token_endpoint_auth_method":"client_secret_basic"}`))
		r.Header.Set("Authorization", "Bearer "+admin)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		api.handler.ServeHTTP(w, r)
		return w
	}
	// Exchange is enabled before any backend exists, because the policy names a client ID
	// that only registration creates. Until then no caller can exchange.
	policy := f.api.config.TokenExchange.Clients[f.client]
	f.api.config.TokenExchange.Clients = conf.ExchangeClients{}
	require.NoError(t, f.api.config.Validate())
	refused := f.exchange(t, f.api, f.subject(t, nil), f.secret, nil)
	require.Equal(t, http.StatusUnauthorized, refused.Code, refused.Body.String())
	require.Contains(t, refused.Body.String(), "invalid_client")

	created := register(f.api)
	require.Equal(t, http.StatusCreated, created.Code, created.Body.String())
	var client struct {
		ID     string `json:"client_id"`
		Secret string `json:"client_secret"`
	}
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &client))

	// The operator names the new registration in the exchange policy and restarts GoTrue.
	// The secret the admin API returned then authenticates an exchange.
	f.api.config.TokenExchange.Clients[client.ID] = policy
	f.client = client.ID
	w := f.exchange(t, f.api, f.subject(t, nil), client.Secret, nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// Exchange uses the registry alone. The endpoints that issue full login tokens stay off.
	for _, route := range [][2]string{
		{http.MethodGet, "/oauth/authorize"}, {http.MethodPost, "/oauth/token"}, {http.MethodPost, "/oauth/clients/register"},
	} {
		w := httptest.NewRecorder()
		f.api.handler.ServeHTTP(w, httptest.NewRequest(route[0], route[1], nil))
		require.Equal(t, http.StatusNotFound, w.Code, route[1])
		require.Contains(t, w.Body.String(), apierrors.ErrorCodeFeatureDisabled, route[1])
	}
	disabled := register(f.legacy)
	require.Equal(t, http.StatusNotFound, disabled.Code, "an API built with neither feature has no registry")
	require.Contains(t, disabled.Body.String(), apierrors.ErrorCodeFeatureDisabled)
}
