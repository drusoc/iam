package account

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	domain "iam/internal/domain/account"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stephenafamo/bob"
	"github.com/stephenafamo/bob/dialect/psql"
	"github.com/stephenafamo/bob/dialect/psql/im"
	"github.com/stephenafamo/bob/dialect/psql/sm"
	"github.com/stephenafamo/bob/dialect/psql/um"
)

var accountColumns = []any{
	"id",
	"google_sub",
	"email",
	"email_verified",
	"status",
	"created_at",
	"updated_at",
}

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Create(ctx context.Context, identity domain.GoogleIdentity) (domain.Account, error) {
	slog.Debug("create account",
		slog.String("google_sub", identity.Sub),
		slog.String("email", identity.Email),
		slog.Bool("email_verified", identity.EmailVerified),
	)
	query := psql.Insert(
		im.Into("accounts", "google_sub", "email", "email_verified", "status"),
		im.Values(psql.Arg(identity.Sub, identity.Email, identity.EmailVerified, domain.StatusActive)),
		im.Returning(accountColumns...),
	)

	account, err := r.queryAccount(ctx, query)
	if err != nil {
		slog.Error("create account",
			slog.Any("error", err),
			slog.String("google_sub", identity.Sub),
		)
		return domain.Account{}, err
	}
	slog.Info("account created",
		slog.Int64("account_id", account.ID),
		slog.String("google_sub", identity.Sub),
		slog.String("email", account.Email),
	)
	return account, nil
}

func (r *Repository) FindByGoogleSub(ctx context.Context, googleSub string) (domain.Account, error) {
	slog.Debug("find account by google sub",
		slog.String("google_sub", googleSub),
	)
	query := psql.Select(
		sm.Columns(accountColumns...),
		sm.From("accounts"),
		sm.Where(psql.Quote("google_sub").EQ(psql.Arg(googleSub))),
		sm.Limit(1),
	)

	account, err := r.queryAccount(ctx, query)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			slog.Debug("account not found by google sub",
				slog.String("google_sub", googleSub),
			)
		} else {
			slog.Error("find account by google sub",
				slog.Any("error", err),
				slog.String("google_sub", googleSub),
			)
		}
		return domain.Account{}, err
	}
	slog.Debug("account found by google sub",
		slog.Int64("account_id", account.ID),
		slog.String("google_sub", googleSub),
	)
	return account, nil
}

func (r *Repository) FindByID(ctx context.Context, id int64) (domain.Account, error) {
	slog.Debug("find account by id",
		slog.Int64("account_id", id),
	)
	query := psql.Select(
		sm.Columns(accountColumns...),
		sm.From("accounts"),
		sm.Where(psql.Quote("id").EQ(psql.Arg(id))),
		sm.Limit(1),
	)

	account, err := r.queryAccount(ctx, query)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			slog.Debug("account not found by id",
				slog.Int64("account_id", id),
			)
		} else {
			slog.Error("find account by id",
				slog.Any("error", err),
				slog.Int64("account_id", id),
			)
		}
		return domain.Account{}, err
	}
	slog.Debug("account found by id",
		slog.Int64("account_id", id),
		slog.String("email", account.Email),
	)
	return account, nil
}

func (r *Repository) SetStatus(ctx context.Context, id int64, status domain.Status) (domain.Account, error) {
	query := psql.Update(
		um.Table("accounts"),
		um.SetCol("status").ToArg(status),
		um.SetCol("updated_at").To("now()"),
		um.Where(psql.Quote("id").EQ(psql.Arg(id))),
		um.Returning(accountColumns...),
	)

	return r.queryAccount(ctx, query)
}

func (r *Repository) queryAccount(ctx context.Context, query bob.Query) (domain.Account, error) {
	sql, args, err := bob.Build(ctx, query)
	if err != nil {
		return domain.Account{}, fmt.Errorf("build account query: %w", err)
	}

	rows, err := r.db.Query(ctx, sql, args...)
	if err != nil {
		return domain.Account{}, fmt.Errorf("query account: %w", err)
	}

	account, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[domain.Account])
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Account{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.Account{}, fmt.Errorf("query account: %w", err)
	}

	return account, nil
}
