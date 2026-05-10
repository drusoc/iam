package oauth

import "errors"

var (
	ErrMissingCode     = errors.New("oauth code is missing")
	ErrMissingState    = errors.New("oauth state is missing")
	ErrInvalidState    = errors.New("oauth state is invalid")
	ErrInvalidToken    = errors.New("oauth token is invalid")
	ErrInvalidAuthCode = errors.New("auth code is invalid")
	ErrMissingAuthCode = errors.New("auth code is missing")
	ErrSessionCreate   = errors.New("failed to create session")
	ErrProviderError   = errors.New("oauth provider error")
)
