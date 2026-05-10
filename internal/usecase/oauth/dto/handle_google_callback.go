package dto

type HandleGoogleCallbackIn struct {
	Code  string
	State string
}

type HandleGoogleCallbackOut struct {
	RedirectURL string
}
