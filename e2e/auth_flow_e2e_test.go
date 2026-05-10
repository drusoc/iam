package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type e2eConfig struct {
	BaseURL         string
	ValidGoogleCode string
}

func TestGoogleStartRedirectContainsRequiredParams(t *testing.T) {
	cfg := loadE2EConfig(t)
	client := noRedirectClient()

	response, err := client.Get(cfg.BaseURL + "/api/1/auth/google/start")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, response.Body.Close())
	})

	require.Equal(t, http.StatusFound, response.StatusCode)

	location, err := url.Parse(response.Header.Get("Location"))
	require.NoError(t, err)
	query := location.Query()

	assert.NotEmpty(t, query.Get("client_id"))
	assert.NotEmpty(t, query.Get("redirect_uri"))
	assert.Equal(t, "code", query.Get("response_type"))
	assert.NotEmpty(t, query.Get("scope"))
	assert.NotEmpty(t, query.Get("state"))
}

func TestGoogleCallbackMissingStateRedirectsToError(t *testing.T) {
	cfg := loadE2EConfig(t)
	client := noRedirectClient()

	response, err := client.Get(cfg.BaseURL + "/api/1/auth/google/callback?code=dummy")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, response.Body.Close())
	})

	require.Equal(t, http.StatusFound, response.StatusCode)
	location, err := url.Parse(response.Header.Get("Location"))
	require.NoError(t, err)

	assert.Equal(t, "missing-state", location.Query().Get("error"))
}

func TestGoogleCallbackMissingCodeRedirectsToError(t *testing.T) {
	cfg := loadE2EConfig(t)
	client := noRedirectClient()

	startResponse, err := client.Get(cfg.BaseURL + "/api/1/auth/google/start")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, startResponse.Body.Close())
	})

	startLocation, err := url.Parse(startResponse.Header.Get("Location"))
	require.NoError(t, err)
	state := startLocation.Query().Get("state")
	require.NotEmpty(t, state)

	callbackURL := cfg.BaseURL + "/api/1/auth/google/callback?state=" + url.QueryEscape(state)
	callbackResponse, err := client.Get(callbackURL)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, callbackResponse.Body.Close())
	})

	require.Equal(t, http.StatusFound, callbackResponse.StatusCode)
	location, err := url.Parse(callbackResponse.Header.Get("Location"))
	require.NoError(t, err)

	assert.Equal(t, "missing-code", location.Query().Get("error"))
}

func TestExchangeInvalidCodeRejected(t *testing.T) {
	cfg := loadE2EConfig(t)
	client := noRedirectClient()

	request, err := http.NewRequest(
		http.MethodPost,
		cfg.BaseURL+"/api/1/auth/code/exchange",
		bytes.NewBufferString(`{"code":"definitely-invalid"}`),
	)
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/json")

	response, err := client.Do(request)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, response.Body.Close())
	})

	require.Equal(t, http.StatusBadRequest, response.StatusCode)
	payload := parseJSONMap(t, response.Body)
	assert.NotEmpty(t, payload["error"]["message"])
	assert.NotEmpty(t, payload["error"]["code"])
}

func TestGoogleFlowHappyPathWhenValidCodeProvided(t *testing.T) {
	cfg := loadE2EConfig(t)
	if cfg.ValidGoogleCode == "" {
		t.Skip("IAM_E2E_VALID_GOOGLE_CODE is not set in .env.e2e")
	}

	client := noRedirectClient()

	startResponse, err := client.Get(cfg.BaseURL + "/api/1/auth/google/start")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, startResponse.Body.Close())
	})

	startLocation, err := url.Parse(startResponse.Header.Get("Location"))
	require.NoError(t, err)
	state := startLocation.Query().Get("state")
	require.NotEmpty(t, state)

	callbackURL := cfg.BaseURL + "/api/1/auth/google/callback?code=" + url.QueryEscape(cfg.ValidGoogleCode) + "&state=" + url.QueryEscape(state)
	callbackResponse, err := client.Get(callbackURL)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, callbackResponse.Body.Close())
	})

	require.Equal(t, http.StatusFound, callbackResponse.StatusCode)
	callbackLocation, err := url.Parse(callbackResponse.Header.Get("Location"))
	require.NoError(t, err)
	require.NotEmpty(t, callbackLocation.Query().Get("code"))

	exchangeBody := `{"code":"` + callbackLocation.Query().Get("code") + `"}`
	exchangeRequest, err := http.NewRequest(
		http.MethodPost,
		cfg.BaseURL+"/api/1/auth/code/exchange",
		bytes.NewBufferString(exchangeBody),
	)
	require.NoError(t, err)
	exchangeRequest.Header.Set("Content-Type", "application/json")

	exchangeResponse, err := client.Do(exchangeRequest)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, exchangeResponse.Body.Close())
	})

	assert.Equal(t, http.StatusNoContent, exchangeResponse.StatusCode)
	require.Len(t, exchangeResponse.Cookies(), 1)
	assert.Equal(t, "iam_session", exchangeResponse.Cookies()[0].Name)
	assert.NotEmpty(t, exchangeResponse.Cookies()[0].Value)
}

func loadE2EConfig(t *testing.T) e2eConfig {
	t.Helper()

	path := filepath.Clean("../.env.e2e")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("skip e2e: cannot read %s: %v", path, err)
	}

	values := parseDotEnv(string(content))
	if strings.ToLower(strings.TrimSpace(values["IAM_E2E_ENABLED"])) != "true" {
		t.Skip("skip e2e: IAM_E2E_ENABLED is not true in .env.e2e")
	}

	baseURL := strings.TrimRight(strings.TrimSpace(values["IAM_E2E_BASE_URL"]), "/")
	if baseURL == "" {
		t.Skip("skip e2e: IAM_E2E_BASE_URL is missing in .env.e2e")
	}

	ensureAppAvailable(t, baseURL)

	return e2eConfig{
		BaseURL:         baseURL,
		ValidGoogleCode: strings.TrimSpace(values["IAM_E2E_VALID_GOOGLE_CODE"]),
	}
}

func ensureAppAvailable(t *testing.T, baseURL string) {
	t.Helper()

	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get(baseURL + "/healthz")
	if err != nil {
		t.Skipf("skip e2e: app is not reachable at %s: %v", baseURL, err)
	}
	defer func() {
		require.NoError(t, response.Body.Close())
	}()

	if response.StatusCode < 200 || response.StatusCode >= 500 {
		t.Skipf("skip e2e: unexpected healthz status %d at %s", response.StatusCode, baseURL)
	}
}

func parseDotEnv(content string) map[string]string {
	result := make(map[string]string)

	for _, rawLine := range strings.Split(content, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		separator := strings.Index(line, "=")
		if separator == -1 {
			continue
		}

		key := strings.TrimSpace(line[:separator])
		value := strings.TrimSpace(line[separator+1:])
		result[key] = strings.Trim(value, `"'`)
	}

	return result
}

func parseJSONMap(t *testing.T, body io.Reader) map[string]map[string]string {
	t.Helper()

	data, err := io.ReadAll(body)
	require.NoError(t, err)

	result := make(map[string]map[string]string)
	require.NoError(t, json.Unmarshal(data, &result))

	return result
}

func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
