package config

import (
	"context"
	"os"
	"time"

	fasterrors "github.com/go-faster/errors"
	"github.com/go-playground/validator/v10"
	"github.com/sethvargo/go-envconfig"
)

type Config struct {
	HTTP     HTTPConfig
	Postgres PostgresConfig
	Redis    RedisConfig
	Google   GoogleOAuthConfig
	Auth     AuthConfig
}

type HTTPConfig struct {
	Addr string `env:"HTTP_ADDR, required" validate:"required"`
}

type PostgresConfig struct {
	DSN string `env:"POSTGRES_DSN, required" validate:"required"`
}

type RedisConfig struct {
	Addr     string `env:"REDIS_ADDR, required" validate:"required"`
	Password string `env:"REDIS_PASSWORD"`
	DB       int    `env:"REDIS_DB, required" validate:"gte=0"`
}

type GoogleOAuthConfig struct {
	ClientID     string   `env:"GOOGLE_CLIENT_ID, required" validate:"required"`
	ClientSecret string   `env:"GOOGLE_CLIENT_SECRET, required" validate:"required"`
	AuthURL      string   `env:"GOOGLE_AUTH_URL, required" validate:"required,url"`
	TokenURL     string   `env:"GOOGLE_TOKEN_URL, required" validate:"required,url"`
	RedirectURL  string   `env:"GOOGLE_REDIRECT_URL, required" validate:"required,url"`
	Scopes       []string `env:"GOOGLE_SCOPES, required" validate:"required,min=1,dive,required"`
}

type AuthConfig struct {
	SuccessURL         string        `env:"APP_AUTH_SUCCESS_URL, required" validate:"required,url"`
	ErrorURL           string        `env:"APP_AUTH_ERROR_URL, required" validate:"required,url"`
	SessionTTL         time.Duration `env:"IAM_SESSION_TTL, required" validate:"gt=0"`
	RefreshTTL         time.Duration `env:"IAM_REFRESH_TTL, required" validate:"gt=0"`
	RefreshAbsoluteTTL time.Duration `env:"IAM_REFRESH_ABSOLUTE_TTL, required" validate:"gt=0"`
	StateTTL           time.Duration `env:"IAM_OAUTH_STATE_TTL, required" validate:"gt=0"`
	CodeTTL            time.Duration `env:"IAM_AUTH_CODE_TTL, required" validate:"gt=0"`
}

type lookupFunc func(string) (string, bool)

func Load() (Config, error) {
	return LoadFromLookup(os.LookupEnv)
}

func LoadFromLookup(lookup lookupFunc) (Config, error) {
	var cfg Config

	if err := envconfig.ProcessWith(context.Background(), &envconfig.Config{
		Target:   &cfg,
		Lookuper: envconfig.LookuperFunc(lookup),
	}); err != nil {
		return Config{}, fasterrors.Wrap(err, "load config")
	}

	if err := validator.New().Struct(cfg); err != nil {
		return Config{}, fasterrors.Wrap(err, "validate config")
	}

	return cfg, nil
}
