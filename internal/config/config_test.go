package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadFromLookup(t *testing.T) {
	tests := []struct {
		name  string
		setup func() lookupFunc
		check func(t *testing.T, cfg Config, err error)
	}{
		{
			name: "valid",
			setup: func() lookupFunc {
				return lookupFromMap(validEnv())
			},
			check: func(t *testing.T, cfg Config, err error) {
				require.NoError(t, err)

				assert.Equal(t, ":8080", cfg.HTTP.Addr)
				assert.Equal(t, 0, cfg.Redis.DB)
				assert.Equal(t, 24*time.Hour, cfg.Auth.SessionTTL)
				assert.Equal(t, []string{"openid", "email", "profile"}, cfg.Google.Scopes)
			},
		},
		{
			name: "missing_required",
			setup: func() lookupFunc {
				env := validEnv()
				delete(env, "GOOGLE_CLIENT_SECRET")
				return lookupFromMap(env)
			},
			check: func(t *testing.T, _ Config, err error) {
				require.Error(t, err)
				assert.ErrorContains(t, err, "GOOGLE_CLIENT_SECRET")
			},
		},
		{
			name: "invalid_redis_db",
			setup: func() lookupFunc {
				env := validEnv()
				env["REDIS_DB"] = "not-int"
				return lookupFromMap(env)
			},
			check: func(t *testing.T, _ Config, err error) {
				require.Error(t, err)
				assert.ErrorContains(t, err, "DB")
			},
		},
		{
			name: "invalid_ttl",
			setup: func() lookupFunc {
				env := validEnv()
				env["IAM_AUTH_CODE_TTL"] = "0s"
				return lookupFromMap(env)
			},
			check: func(t *testing.T, _ Config, err error) {
				require.Error(t, err)
				assert.ErrorContains(t, err, "CodeTTL")
				assert.ErrorContains(t, err, "gt")
			},
		},
		{
			name: "empty_google_scopes",
			setup: func() lookupFunc {
				env := validEnv()
				env["GOOGLE_SCOPES"] = ""
				return lookupFromMap(env)
			},
			check: func(t *testing.T, _ Config, err error) {
				require.Error(t, err)
				assert.ErrorContains(t, err, "Scopes")
			},
		},
		{
			name: "blank_google_scope_item",
			setup: func() lookupFunc {
				env := validEnv()
				env["GOOGLE_SCOPES"] = "openid,,profile"
				return lookupFromMap(env)
			},
			check: func(t *testing.T, _ Config, err error) {
				require.Error(t, err)
				assert.ErrorContains(t, err, "Scopes")
				assert.ErrorContains(t, err, "required")
			},
		},
		{
			name: "invalid_url",
			setup: func() lookupFunc {
				env := validEnv()
				env["GOOGLE_TOKEN_URL"] = "not-url"
				return lookupFromMap(env)
			},
			check: func(t *testing.T, _ Config, err error) {
				require.Error(t, err)
				assert.ErrorContains(t, err, "TokenURL")
				assert.ErrorContains(t, err, "url")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadFromLookup(tt.setup())

			tt.check(t, cfg, err)
		})
	}
}

func validEnv() map[string]string {
	return map[string]string{
		"HTTP_ADDR":                ":8080",
		"POSTGRES_DSN":             "postgres://iam:iam@localhost:5432/iam?sslmode=disable",
		"REDIS_ADDR":               "localhost:6379",
		"REDIS_PASSWORD":           "",
		"REDIS_DB":                 "0",
		"GOOGLE_CLIENT_ID":         "local-client-id.apps.googleusercontent.com",
		"GOOGLE_CLIENT_SECRET":     "local-client-secret",
		"GOOGLE_AUTH_URL":          "https://accounts.google.com/o/oauth2/auth",
		"GOOGLE_TOKEN_URL":         "https://oauth2.googleapis.com/token",
		"GOOGLE_REDIRECT_URL":      "http://localhost:8080/api/1/auth/google/callback",
		"GOOGLE_SCOPES":            "openid,email,profile",
		"APP_AUTH_SUCCESS_URL":     "http://localhost:3000/auth/success",
		"APP_AUTH_ERROR_URL":       "http://localhost:3000/auth/error",
		"IAM_SESSION_TTL":          "24h",
		"IAM_REFRESH_TTL":          "720h",
		"IAM_REFRESH_ABSOLUTE_TTL": "2160h",
		"IAM_OAUTH_STATE_TTL":      "10m",
		"IAM_AUTH_CODE_TTL":        "2m",
	}
}

func lookupFromMap(values map[string]string) lookupFunc {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}
