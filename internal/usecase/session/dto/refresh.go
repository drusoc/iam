package dto

type RefreshIn struct {
	RefreshToken string
}

type RefreshOut struct {
	SessionID    string
	RefreshToken string
}
