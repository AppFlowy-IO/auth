package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/gobwas/glob"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/models"
)

func (ts *SSOTestSuite) TestSAMLACSErrorRedirect() {
	const siteURL = "appflowy-flutter://login-callback"
	const browserURL = "https://admin.example.com/console/sso-callback?test=saml"
	originalSiteURL, originalAllowList := ts.Config.SiteURL, ts.Config.URIAllowListMap
	ts.Config.SiteURL = siteURL
	ts.Config.URIAllowListMap = map[string]glob.Glob{browserURL: glob.MustCompile(browserURL)}
	defer func() {
		ts.Config.SiteURL = originalSiteURL
		ts.Config.URIAllowListMap = originalAllowList
	}()

	providerID := ts.createACSProvider()
	for _, tc := range []struct {
		name       string
		redirectTo string
		expired    bool
		wantURL    string
		wantCode   string
	}{
		{"browser validation failure", browserURL, false, browserURL, "validation_failed"},
		{"browser expired state", browserURL, true, browserURL, "saml_relay_state_expired"},
		{"desktop validation failure", siteURL, false, siteURL, "validation_failed"},
		{"unapproved callback", "https://untrusted.example.com/callback", false, siteURL, "validation_failed"},
		{"empty callback", "", false, siteURL, "validation_failed"},
	} {
		ts.Run(tc.name, func() {
			relayID := ts.initiateACSLogin(providerID, tc.redirectTo)
			relay, err := models.FindSAMLRelayStateByID(ts.API.db, relayID)
			require.NoError(ts.T(), err)
			if tc.expired {
				relay.CreatedAt = time.Now().Add(-ts.Config.SAML.RelayStateValidityPeriod - time.Second)
				require.NoError(ts.T(), ts.API.db.RawQuery("UPDATE saml_relay_states SET created_at = ? WHERE id = ?", relay.CreatedAt, relayID).Exec())
			}

			location := ts.postInvalidACS(relayID.String())
			require.Equal(ts.T(), tc.wantCode, location.Query().Get("error_code"))
			require.NotEmpty(ts.T(), location.Query().Get("error_description"))
			query := location.Query()
			for _, key := range []string{"error", "error_code", "error_description", "error_id"} {
				query.Del(key)
			}
			location.RawQuery = query.Encode()
			require.Equal(ts.T(), tc.wantURL, location.String())
			_, err = models.FindSAMLRelayStateByID(ts.API.db, relayID)
			require.True(ts.T(), models.IsNotFoundError(err), "the error callback must survive RelayState consumption")
		})
	}

	// A request without a server-stored RelayState must not select its error callback.
	for _, relay := range []string{"", uuid.Must(uuid.NewV4()).String(), browserURL, "https://untrusted.example.com"} {
		location := ts.postInvalidACS(relay)
		require.NotEmpty(ts.T(), location.Query().Get("error_code"))
		location.RawQuery = ""
		require.Equal(ts.T(), siteURL, location.String())
	}
}

func (ts *SSOTestSuite) createACSProvider() string {
	body, err := json.Marshal(map[string]interface{}{
		"type": "saml", "metadata_xml": validSAMLIDPMetadata("https://idp.example.com/saml"),
	})
	require.NoError(ts.T(), err)
	req := httptest.NewRequest(http.MethodPost, "http://localhost/admin/sso/providers", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+ts.AdminJWT)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
	var provider struct{ ID string }
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&provider))
	return provider.ID
}

func (ts *SSOTestSuite) initiateACSLogin(providerID, redirectTo string) uuid.UUID {
	body, err := json.Marshal(map[string]interface{}{
		"provider_id": providerID, "redirect_to": redirectTo, "skip_http_redirect": true,
	})
	require.NoError(ts.T(), err)
	req := httptest.NewRequest(http.MethodPost, "http://localhost/sso", bytes.NewReader(body))
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	var response struct{ URL string }
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&response))
	redirect, err := url.Parse(response.URL)
	require.NoError(ts.T(), err)
	relayID, err := uuid.FromString(redirect.Query().Get("RelayState"))
	require.NoError(ts.T(), err)
	return relayID
}

func (ts *SSOTestSuite) postInvalidACS(relayState string) *url.URL {
	form := url.Values{
		"RelayState": {relayState}, "SAMLResponse": {"invalid-base64"},
		"redirect_to": {"https://admin.example.com/console/sso-callback?test=saml"},
	}
	req := httptest.NewRequest(http.MethodPost, "http://localhost/sso/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "https://admin.example.com/console/sso-callback?test=saml")
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusSeeOther, w.Code, w.Body.String())
	location, err := url.Parse(w.Header().Get("Location"))
	require.NoError(ts.T(), err)
	return location
}
