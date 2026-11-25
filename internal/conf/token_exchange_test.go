package conf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/require"
)

func TestTokenExchangeConfiguration(t *testing.T) {
	const secret = "private-key-material-must-not-be-logged"
	clear := func() {
		for _, name := range exchangeSettings {
			t.Setenv("GOTRUE_TOKEN_EXCHANGE_"+name, "")
		}
	}
	// A deployment file forwards every setting to every installation: the unset ones as
	// empty strings and the limits with their defaults. That is exchange turned off.
	clear()
	t.Setenv("GOTRUE_TOKEN_EXCHANGE_RATE_LIMIT", "150")
	t.Setenv("GOTRUE_TOKEN_EXCHANGE_MAX_CONCURRENT", "8")
	var c TokenExchangeConfiguration
	require.NoError(t, c.load())
	require.False(t, c.Enabled)
	require.NoError(t, c.validate(nil))

	// Any exchange setting turns it on. An unusable key fails without being echoed.
	t.Setenv("GOTRUE_TOKEN_EXCHANGE_SIGNING_KEYS", secret)
	err := c.load()
	require.Error(t, err)
	require.NotContains(t, err.Error(), secret)

	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.FromRaw(raw)
	require.NoError(t, err)
	require.NoError(t, key.Set("alg", "ES256"))
	require.NoError(t, key.Set("kid", "exchange-test"))
	require.NoError(t, key.Set("key_ops", jwk.KeyOperationList{jwk.KeyOpSign}))
	keys, err := json.Marshal([]jwk.Key{key})
	require.NoError(t, err)
	t.Setenv("GOTRUE_TOKEN_EXCHANGE_SIGNING_KEYS", string(keys))
	// There is no switch to forget. A partly configured exchange stops startup and names
	// the setting that is missing, whichever part was configured first.
	require.NoError(t, c.load())
	require.True(t, c.Enabled)
	require.ErrorContains(t, c.validate(nil), "GOTRUE_TOKEN_EXCHANGE_TENANT_ID")
	t.Setenv("GOTRUE_TOKEN_EXCHANGE_TENANT_ID", "11111111-1111-4111-8111-111111111111")
	require.NoError(t, c.load())
	require.ErrorContains(t, c.validate(nil), "GOTRUE_TOKEN_EXCHANGE_PROVIDER")
	t.Setenv("GOTRUE_TOKEN_EXCHANGE_PROVIDER", "custom:tenant")
	t.Setenv("GOTRUE_TOKEN_EXCHANGE_SIGNING_KEYS", "")
	require.NoError(t, c.load())
	require.True(t, c.Enabled)
	require.ErrorContains(t, c.validate(nil), "GOTRUE_TOKEN_EXCHANGE_SIGNING_KEYS")
	t.Setenv("GOTRUE_TOKEN_EXCHANGE_SIGNING_KEYS", string(keys))
	const client = "22222222-2222-4222-8222-222222222222"
	t.Setenv("GOTRUE_TOKEN_EXCHANGE_CLIENTS", `{"`+client+`":{"entra_client_id":"33333333-3333-4333-8333-333333333333","audience":"44444444-4444-4444-8444-444444444444","scopes":["data.read"]}}`)
	require.NoError(t, c.load())
	require.NoError(t, c.validate(nil))
	require.Equal(t, 150, c.RateLimit)
	require.Equal(t, 8, c.MaxConcurrent)
	// Before the first backend is registered there is no client ID to name, and a
	// deployment file forwards the unset policy as an empty string.
	for _, none := range []string{"", "{}"} {
		t.Setenv("GOTRUE_TOKEN_EXCHANGE_CLIENTS", none)
		require.NoError(t, c.load(), "clients %q", none)
		require.Empty(t, c.Clients)
		require.NoError(t, c.validate(nil), "clients %q", none)
	}
	t.Setenv("GOTRUE_TOKEN_EXCHANGE_CLIENTS", `{"`+client+`":{"entra_client_id":"33333333-3333-4333-8333-333333333333","audience":"44444444-4444-4444-8444-444444444444","scopes":["data.read"]}}`)
	require.NoError(t, c.load())
	require.Error(t, c.validate(c.SigningKeys.JwtKeysDecoder), "login key cannot also sign delegated access")
	duplicates, err := json.Marshal([]jwk.Key{key, key})
	require.NoError(t, err)
	t.Setenv("GOTRUE_TOKEN_EXCHANGE_SIGNING_KEYS", string(duplicates))
	require.Error(t, c.load(), "a rotation must use a fresh kid")
	t.Setenv("GOTRUE_TOKEN_EXCHANGE_SIGNING_KEYS", string(keys))
	require.NoError(t, c.load())
	policy := c.Clients[client]
	policy.Audience = policy.EntraClientID
	c.Clients[client] = policy
	require.Error(t, c.validate(nil), "dashboard is a different audience from the resource")
	// Removing the settings turns exchange off again and leaves nothing behind.
	clear()
	require.NoError(t, c.load())
	require.Equal(t, TokenExchangeConfiguration{}, c)
}
