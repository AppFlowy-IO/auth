package conf

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/kelseyhightower/envconfig"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// TokenExchangeConfiguration contains the installation's explicit delegation policy.
// The resource and client IDs are Entra application IDs. Only existing GoTrue
// confidential clients listed here can act on behalf of a user. A policy with no
// clients refuses every exchange and opens the admin client registry, which is how
// the first backend gets the client ID that this policy then names.
type TokenExchangeConfiguration struct {
	// Enabled is derived, never read from the environment: exchange is on exactly
	// when the installation configures it. See load.
	Enabled       bool   `ignored:"true"`
	TenantID      string `split_words:"true"`
	Provider      string
	Clients       ExchangeClients
	SigningKeys   ExchangeSigningKeys `split_words:"true" json:"-"`
	RateLimit     int                 `split_words:"true" default:"150"`
	MaxConcurrent int                 `split_words:"true" default:"8"`
}

// ExchangeClient binds a confidential GoTrue client to an Entra caller and one resource.
type ExchangeClient struct {
	EntraClientID string   `json:"entra_client_id"`
	Audience      string   `json:"audience"`
	Scopes        []string `json:"scopes"`
}

// ExchangeClients is keyed by the GoTrue client registration ID.
type ExchangeClients map[string]ExchangeClient

// Decode accepts an empty value as no clients. A deployment file that forwards the
// setting sends an empty string until the first backend has been registered.
func (c *ExchangeClients) Decode(value string) error {
	if strings.TrimSpace(value) == "" {
		*c = ExchangeClients{}
		return nil
	}
	return json.Unmarshal([]byte(value), c)
}

// ExchangeSigningKeys requires a distinct kid for each key so rotations remain verifiable.
type ExchangeSigningKeys struct{ JwtKeysDecoder }

func (k *ExchangeSigningKeys) Decode(value string) error {
	// A deployment file forwards an unset value as an empty string. validate names
	// the missing setting when the rest of the exchange is configured.
	if strings.TrimSpace(value) == "" {
		k.JwtKeysDecoder = JwtKeysDecoder{}
		return nil
	}
	var entries []json.RawMessage
	if err := json.Unmarshal([]byte(value), &entries); err != nil {
		return err
	}
	keys := make(JwtKeysDecoder, len(entries))
	for i, entry := range entries {
		if err := keys.decodeKey(keys, entry); err != nil {
			return err
		}
		if len(keys) != i+1 {
			return fmt.Errorf("duplicate token exchange signing key ID")
		}
	}
	k.JwtKeysDecoder = keys
	return nil
}

// exchangeSettings turn exchange on when any of them has a value. There is no separate
// switch: an installation that configures none of them never parses or serves anything,
// and one that configures only some of them fails validation at startup instead of
// running with exchange silently off. The two limits are not listed, because deployment
// files forward their defaults to every installation.
var exchangeSettings = []string{"TENANT_ID", "PROVIDER", "CLIENTS", "SIGNING_KEYS"}

func (c *TokenExchangeConfiguration) load() error {
	const prefix = "GOTRUE_TOKEN_EXCHANGE"
	configured := slices.ContainsFunc(exchangeSettings, func(name string) bool {
		return strings.TrimSpace(os.Getenv(prefix+"_"+name)) != ""
	})
	*c = TokenExchangeConfiguration{}
	if !configured {
		return nil
	}
	if err := envconfig.Process(prefix, c); err != nil {
		// envconfig includes the original environment value in conversion errors.
		if field, ok := err.(*envconfig.ParseError); ok && field.FieldName == "SigningKeys" {
			return fmt.Errorf("invalid token exchange signing key configuration")
		}
		return err
	}
	c.Enabled = true
	return nil
}

func (c *TokenExchangeConfiguration) validate(loginKeys JwtKeysDecoder) error {
	if !c.Enabled {
		return nil
	}
	validID := func(s string) bool {
		id, err := uuid.FromString(s)
		return err == nil && id != uuid.Nil && id.String() == s
	}
	if !validID(c.TenantID) || !strings.HasPrefix(c.Provider, "custom:") || len(c.Provider) <= len("custom:") {
		return fmt.Errorf("token exchange requires GOTRUE_TOKEN_EXCHANGE_TENANT_ID as a lowercase tenant UUID and GOTRUE_TOKEN_EXCHANGE_PROVIDER as a custom OIDC provider identifier")
	}
	if len(c.SigningKeys.JwtKeysDecoder) == 0 {
		return fmt.Errorf("token exchange requires GOTRUE_TOKEN_EXCHANGE_SIGNING_KEYS")
	}
	if c.RateLimit <= 0 || c.MaxConcurrent <= 0 {
		return fmt.Errorf("token exchange rate and concurrency limits must be positive")
	}
	for id, policy := range c.Clients {
		if !validID(id) || !validID(policy.EntraClientID) || !validID(policy.Audience) || policy.EntraClientID == policy.Audience || len(policy.Scopes) == 0 {
			return fmt.Errorf("invalid token exchange client registration %q", id)
		}
		for _, scope := range policy.Scopes {
			if scope == "" || strings.ContainsAny(scope, " \"\\") || strings.IndexFunc(scope, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 {
				return fmt.Errorf("invalid token exchange scope for client %q", id)
			}
		}
	}
	if err := c.SigningKeys.Validate(); err != nil {
		return fmt.Errorf("token exchange signing keys: %w", err)
	}
	for kid, key := range c.SigningKeys.JwtKeysDecoder {
		var pub ecdsa.PublicKey
		if kid == "" || key.PublicKey == nil || key.PublicKey.Algorithm() == nil || key.PublicKey.Algorithm().String() != "ES256" || key.PublicKey.Raw(&pub) != nil || pub.Curve != elliptic.P256() {
			return fmt.Errorf("token exchange requires named ES256 P-256 keys")
		}
		if slices.Contains(key.PrivateKey.KeyOps(), jwk.KeyOpSign) {
			var private ecdsa.PrivateKey
			if key.PrivateKey.Raw(&private) != nil {
				return fmt.Errorf("token exchange signing key must be private")
			}
		}
		exchangePrint, err := key.PublicKey.Thumbprint(crypto.SHA256)
		if err != nil {
			return err
		}
		for _, loginKey := range loginKeys {
			loginPrint, err := loginKey.PrivateKey.Thumbprint(crypto.SHA256)
			if err != nil {
				return err
			}
			if bytes.Equal(exchangePrint, loginPrint) {
				return fmt.Errorf("token exchange and login signing keys must be distinct")
			}
		}
	}
	return nil
}
