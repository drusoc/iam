package dto

type ExchangeAuthCodeIn struct {
	Code string
}

type ExchangeAuthCodeOut struct {
	SessionID    string
	RefreshToken string
}
