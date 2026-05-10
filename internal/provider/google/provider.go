package google

import (
	"context"

	fasterrors "github.com/go-faster/errors"
	"iam/internal/config"

	domain "iam/internal/domain/account"
	oauthdomain "iam/internal/domain/oauth"

	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"
)

type Provider struct {
	config oauth2.Config
}

func NewProvider(cfg config.GoogleOAuthConfig) *Provider {
	return &Provider{
		config: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       cfg.Scopes,
			Endpoint: oauth2.Endpoint{
				TokenURL: cfg.TokenURL,
			},
		},
	}
}

func (p *Provider) ExchangeCode(ctx context.Context, code string) (domain.GoogleIdentity, error) {
	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return domain.GoogleIdentity{}, fasterrors.Wrapf(oauthdomain.ErrProviderError, "exchange google code: %v", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return domain.GoogleIdentity{}, oauthdomain.ErrInvalidToken
	}

	payload, err := idtoken.Validate(ctx, rawIDToken, p.config.ClientID)
	if err != nil {
		return domain.GoogleIdentity{}, fasterrors.Wrapf(oauthdomain.ErrInvalidToken, "validate id token: %v", err)
	}

	email, _ := payload.Claims["email"].(string)
	emailVerified, _ := payload.Claims["email_verified"].(bool)

	return domain.GoogleIdentity{
		Sub:           payload.Subject,
		Email:         email,
		EmailVerified: emailVerified,
	}, nil
}
