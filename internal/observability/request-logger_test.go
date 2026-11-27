package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/utilities"
)

const apiTestConfig = "../../hack/test.env"

func TestLogger(t *testing.T) {
	var logBuffer bytes.Buffer
	config, err := conf.LoadGlobal(apiTestConfig)
	require.NoError(t, err)

	config.Logging.Level = "info"
	require.NoError(t, ConfigureLogging(&config.Logging))

	// logrus should write to the buffer so we can check if the logs are output correctly
	logrus.SetOutput(&logBuffer)

	// add request id header
	config.API.RequestIDHeader = "X-Request-ID"
	addRequestIdHandler := AddRequestID(config)

	logHandler := NewStructuredLogger(logrus.StandardLogger(), config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodPost, "http://example.com/path", nil)
	req.Header.Add("X-Request-ID", "test-request-id")
	require.NoError(t, err)
	addRequestIdHandler(logHandler).ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var logs map[string]interface{}
	require.NoError(t, json.NewDecoder(&logBuffer).Decode(&logs))
	require.Equal(t, "api", logs["component"])
	require.Equal(t, http.MethodPost, logs["method"])
	require.Equal(t, "/path", logs["path"])
	require.Equal(t, "test-request-id", logs["request_id"])
	require.NotNil(t, logs["time"])
}

func TestPasswordGrantRequestID(t *testing.T) {
	for _, tc := range []struct {
		name, configuredHeader string
		values                 []string
		want                   string // Empty when Auth should generate a UUID.
	}{
		{"default", "", []string{"Req.Login_1-2"}, "Req.Login_1-2"},
		{"longest", "", []string{strings.Repeat("a", 128)}, strings.Repeat("a", 128)},
		{"upstream header", "X-Proxy-ID", []string{"Proxy-42"}, "Proxy-42"},
		{"configured header missing", "X-Proxy-ID", nil, ""},
		{"missing", "", nil, ""},
		{"empty", "", []string{""}, ""},
		{"duplicate", "", []string{"first", "second"}, ""},
		{"combined", "", []string{"first, second"}, ""},
		{"dot", "", []string{"."}, ""},
		{"dot dot", "", []string{".."}, ""},
		{"unsearchable", "", []string{"a/b"}, ""},
		{"too long", "", []string{strings.Repeat("a", 129)}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := &conf.GlobalConfiguration{}
			config.API.RequestIDHeader = tc.configuredHeader
			req := httptest.NewRequest(http.MethodPost, "/token?grant_type=password", strings.NewReader(`{"password":"private-test-password"}`))
			req.Header.Set("Content-Type", "application/json")
			header := tc.configuredHeader
			if header == "" {
				header = RequestIDHeader
			} else {
				req.Header.Set(RequestIDHeader, "untrusted-alternative")
			}
			for _, value := range tc.values {
				req.Header.Add(header, value)
			}
			var output bytes.Buffer
			logger := logrus.New()
			logger.SetFormatter(&logrus.JSONFormatter{})
			logger.SetOutput(&output)
			var contextID string
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				contextID = utilities.GetRequestID(r.Context())
				w.WriteHeader(http.StatusBadRequest)
			})
			w := httptest.NewRecorder()
			AddRequestID(config)(NewStructuredLogger(logger, config)(handler)).ServeHTTP(w, req)
			id := w.Result().Header.Get(RequestIDHeader)
			if tc.want == "" {
				_, err := uuid.FromString(id)
				require.NoError(t, err)
			} else {
				require.Equal(t, tc.want, id)
			}
			require.Equal(t, id, contextID)
			var record map[string]interface{}
			require.NoError(t, json.Unmarshal(output.Bytes(), &record))
			require.Equal(t, id, record["request_id"])
			require.Equal(t, "/token", record["path"])
			require.Equal(t, "password", record["grant_type"])
			require.EqualValues(t, http.StatusBadRequest, record["status"])
			require.NotContains(t, output.String(), "private-test-password")
		})
	}
}

func TestExcludeHealthFromLogs(t *testing.T) {
	var logBuffer bytes.Buffer
	config, err := conf.LoadGlobal(apiTestConfig)
	require.NoError(t, err)

	config.Logging.Level = "info"
	require.NoError(t, ConfigureLogging(&config.Logging))

	// logrus should write to the buffer so we can check if the logs are output correctly
	logrus.SetOutput(&logBuffer)

	logHandler := NewStructuredLogger(logrus.StandardLogger(), config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "http://example.com/health", nil)
	require.NoError(t, err)
	logHandler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	require.Empty(t, logBuffer)
}

func TestContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	le := &logEntry{Entry: logrus.NewEntry(logrus.StandardLogger())}
	{
		got := GetLogEntryFromContext(ctx)
		if got == le {
			t.Fatal("exp new log entry")
		}
	}

	ctx = SetLogEntryWithContext(ctx, le)
	{
		got := GetLogEntryFromContext(ctx)
		if got != le {
			t.Fatal("exp new log entry")
		}
	}
}
