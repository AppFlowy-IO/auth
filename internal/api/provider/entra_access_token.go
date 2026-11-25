package provider

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gofrs/uuid"
)

// EntraDelegation describes the user and permissions asserted for a downstream API.
// The subject claim is pairwise and can differ from the one used during OIDC sign-in.
type EntraDelegation struct {
	ObjectID string
	Scopes   []string
	Expiry   time.Time
}

// EntraAccessTokens verifies v2 workforce access tokens for a configured public-cloud tenant.
// The trusted key endpoint never comes from a request. RemoteKeySet caches keys across clients.
type EntraAccessTokens struct {
	tenant string
	keys   oidc.KeySet
}

// ErrEntraKeysUnavailable indicates that a verifier could not retrieve signing keys.
var ErrEntraKeysUnavailable = errors.New("signing keys for Entra are unavailable")

func NewEntraAccessTokens(tenant string, client *http.Client) *EntraAccessTokens {
	ctx := oidc.ClientContext(context.Background(), client)
	keys := oidc.NewRemoteKeySet(ctx, "https://login.microsoftonline.com/"+tenant+"/discovery/v2.0/keys")
	return &EntraAccessTokens{tenant: tenant, keys: keys}
}

func (v *EntraAccessTokens) Issuer() string {
	return "https://login.microsoftonline.com/" + v.tenant + "/v2.0"
}

func (v *EntraAccessTokens) Verify(ctx context.Context, raw, audience, caller string, now time.Time) (*EntraDelegation, error) {
	verifier := oidc.NewVerifier(v.Issuer(), v.keys, &oidc.Config{
		ClientID: audience, SupportedSigningAlgs: []string{oidc.RS256}, Now: func() time.Time { return now },
	})
	token, err := verifier.Verify(ctx, raw)
	if err != nil {
		// go-oidc v3.6 formats key-fetch errors at both layers without wrapping
		// them. Only this path indicates failed key retrieval, not a bad signature.
		if ctx.Err() != nil || strings.HasPrefix(err.Error(), "failed to verify signature: fetching keys ") {
			return nil, ErrEntraKeysUnavailable
		}
		return nil, err
	}
	var claims struct {
		Version      string `json:"ver"`
		Tenant       string `json:"tid"`
		ObjectID     string `json:"oid"`
		Caller       string `json:"azp"`
		IdentityType string `json:"idtyp"`
		Scope        string `json:"scp"`
		NotBefore    int64  `json:"nbf"`
	}
	if err := token.Claims(&claims); err != nil {
		return nil, err
	}
	id, err := uuid.FromString(claims.ObjectID)
	scopes := strings.Fields(claims.Scope)
	if err != nil || id == uuid.Nil || token.Subject == "" || claims.Version != "2.0" ||
		claims.Tenant != v.tenant || claims.Caller != caller || (claims.IdentityType != "" && claims.IdentityType != "user") ||
		len(token.Audience) != 1 || len(scopes) == 0 || claims.NotBefore > now.Unix() || !token.Expiry.After(now) {
		return nil, errors.New("invalid Entra delegated access token")
	}
	return &EntraDelegation{ObjectID: id.String(), Scopes: scopes, Expiry: token.Expiry}, nil
}
