package dto

type LogoutIn struct {
	SessionID    string
	RefreshToken string
}

type LogoutOut struct{}
