package postgres

import (
	"auction/domain"
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"
)

type PgRepository struct {
	db *sqlx.DB
}

func NewPgRepository(host, database, user, password, port string) *PgRepository {
	db := sqlx.MustConnect("postgres", fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, database,
	))
	return &PgRepository{db: db}
}

func (r *PgRepository) Close() error {
	return r.db.Close()
}

func (r *PgRepository) FindByID(ctx context.Context, id string) (*domain.User, error) {
	var user domain.User
	err := r.db.GetContext(ctx, &user, "SELECT * FROM users WHERE id = $1", id)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *PgRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	var user domain.User
	err := r.db.GetContext(ctx, &user, "SELECT * FROM users WHERE email = $1", email)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *PgRepository) Create(ctx context.Context, email, password, name string) (string, error) {
	var id string
	query := `INSERT INTO users (email, password, name) VALUES ($1, $2, $3) RETURNING id`
	err := r.db.GetContext(ctx, &id, query, email, password, name)
	return id, err
}

func (r *PgRepository) Update(ctx context.Context, id, email, name string) error {
	_, err := r.db.ExecContext(ctx, "UPDATE users SET email = $1, name = $2 WHERE id = $3", email, name, id)
	return err
}

func (r *PgRepository) EnableTwoFactor(ctx context.Context, id, secret string) error {
	query := `UPDATE users SET two_factor_enabled = TRUE, two_factor_secret = $1 WHERE id = $2`
	_, err := r.db.ExecContext(ctx, query, secret, id)
	return err
}

func (r *PgRepository) DisableTwoFactor(ctx context.Context, id string) error {
	query := `UPDATE users SET two_factor_enabled = FALSE, two_factor_secret = NULL, two_factor_verified = FALSE WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *PgRepository) MarkTwoFactorVerified(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, "UPDATE users SET two_factor_verified = TRUE WHERE id = $1", id)
	return err
}

func (r *PgRepository) SetRecoveryCodes(ctx context.Context, id, codes string) error {
	_, err := r.db.ExecContext(ctx, "UPDATE users SET two_factor_recovery_codes = $1 WHERE id = $2", codes, id)
	return err
}