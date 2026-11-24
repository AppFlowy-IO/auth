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
	t.Setenv("GOTRUE_TOKEN_EXCHANGE_ENABLED", "false")
	t.Setenv("GOTRUE_TOKEN_EXCHANGE_SIGNING_KEYS", secret)
	var c TokenExchangeConfiguration
	require.NoError(t, c.load())
	require.NoError(t, c.validate(nil))

	t.Setenv("GOTRUE_TOKEN_EXCHANGE_ENABLED", "true")
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
	t.Setenv("GOTRUE_TOKEN_EXCHANGE_TENANT_ID", "11111111-1111-4111-8111-111111111111")
	t.Setenv("GOTRUE_TOKEN_EXCHANGE_PROVIDER", "custom:tenant")
	const client = "22222222-2222-4222-8222-222222222222"
	t.Setenv("GOTRUE_TOKEN_EXCHANGE_CLIENTS", `{"`+client+`":{"entra_client_id":"33333333-3333-4333-8333-333333333333","audience":"44444444-4444-4444-8444-444444444444","scopes":["data.read"]}}`)
	require.NoError(t, c.load())
	require.NoError(t, c.validate(nil))
	require.Equal(t, 150, c.RateLimit)
	require.Equal(t, 8, c.MaxConcurrent)
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
	t.Setenv("GOTRUE_TOKEN_EXCHANGE_ENABLED", "false")
	require.NoError(t, c.load())
	require.False(t, c.Enabled)
}
