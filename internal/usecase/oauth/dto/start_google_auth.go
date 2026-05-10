package dto

type StartGoogleAuthIn struct{}

type StartGoogleAuthOut struct {
	RedirectURL string
	State       string
}
