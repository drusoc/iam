package main

import (
	"context"
	"log/slog"
	"os"

	"iam/internal/config"
	"iam/internal/httpserver"
	"iam/internal/postgres"
	googlerepo "iam/internal/provider/google"
	"iam/internal/redis"
	accountrepo "iam/internal/repository/postgres/account"
	redisrepooauth "iam/internal/repository/redis/oauth"
	redisreposession "iam/internal/repository/redis/session"
	authtransport "iam/internal/transport/http/auth"
	accountusecase "iam/internal/usecase/account"
	oauthusecase "iam/internal/usecase/oauth"
	sessionusecase "iam/internal/usecase/session"

	"github.com/joho/godotenv"
)

func main() {
	ctx := context.Background()

	slog.Info("starting application")

	err := godotenv.Load()
	if err != nil {
		slog.Warn("load .env file", slog.Any("error", err))
	}

	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config", slog.Any("error", err))
		os.Exit(1)
	}

	slog.Info("config loaded",
		slog.String("http_addr", cfg.HTTP.Addr),
		slog.String("log_level", "debug"),
	)

	postgresPool, err := postgres.NewPool(ctx, cfg.Postgres.DSN)
	if err != nil {
		slog.Error("connect postgres", slog.Any("error", err))
		os.Exit(1)
	}
	defer postgresPool.Close()
	slog.Info("postgres connected")

	redisClient := redis.NewClient(cfg.Redis.Addr, cfg.Redis.Password, cfg.Redis.DB)
	defer func() {
		if closeErr := redisClient.Close(); closeErr != nil {
			slog.Error("close redis", slog.Any("error", closeErr))
		}
	}()

	if err = redis.Ping(ctx, redisClient); err != nil {
		slog.Error("ping redis", slog.Any("error", err))
		os.Exit(1)
	}
	slog.Info("redis connected")

	accountRepository := accountrepo.NewRepository(postgresPool)
	accountUC := accountusecase.NewUsecase(accountRepository)
	stateRepository := redisrepooauth.NewStateRepository(redisClient)
	authCodeRepository := redisrepooauth.NewAuthCodeRepository(redisClient)
	sessionRepository := redisreposession.NewRepository(redisClient)
	refreshRepository := redisreposession.NewRefreshRepository(redisClient)
	googleProvider := googlerepo.NewProvider(cfg.Google)
	oauthUC := oauthusecase.NewUsecase(
		oauthusecase.Config{
			ClientID:           cfg.Google.ClientID,
			AuthURL:            cfg.Google.AuthURL,
			RedirectURL:        cfg.Google.RedirectURL,
			AppSuccessURL:      cfg.Auth.SuccessURL,
			Scopes:             cfg.Google.Scopes,
			StateTTL:           cfg.Auth.StateTTL,
			AuthCodeTTL:        cfg.Auth.CodeTTL,
			SessionTTL:         cfg.Auth.SessionTTL,
			RefreshTTL:         cfg.Auth.RefreshTTL,
			RefreshAbsoluteTTL: cfg.Auth.RefreshAbsoluteTTL,
		},
		stateRepository,
		authCodeRepository,
		sessionRepository,
		refreshRepository,
		googleProvider,
		accountUC,
	)
	sessionUC := sessionusecase.NewUsecase(
		sessionusecase.Config{
			SessionTTL:         cfg.Auth.SessionTTL,
			RefreshTTL:         cfg.Auth.RefreshTTL,
			RefreshAbsoluteTTL: cfg.Auth.RefreshAbsoluteTTL,
		},
		sessionRepository,
		refreshRepository,
		accountUC,
	)
	authHandler := authtransport.NewHandler(oauthUC, sessionUC, cfg.Auth)

	server := httpserver.New(authHandler)
	if err = server.Start(cfg.HTTP.Addr); err != nil {
		slog.Error("start http server", slog.Any("error", err))
		os.Exit(1)
	}
}
