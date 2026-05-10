package account

import "time"

type Status string

const (
	StatusActive  Status = "active"
	StatusBlocked Status = "blocked"
	StatusDeleted Status = "deleted"
)

type Account struct {
	ID            int64     `db:"id"`
	GoogleSub     string    `db:"google_sub"`
	Email         string    `db:"email"`
	EmailVerified bool      `db:"email_verified"`
	Status        Status    `db:"status"`
	CreatedAt     time.Time `db:"created_at"`
	UpdatedAt     time.Time `db:"updated_at"`
}

type GoogleIdentity struct {
	Sub           string `db:"sub"`
	Email         string `db:"email"`
	EmailVerified bool   `db:"email_verified"`
}
