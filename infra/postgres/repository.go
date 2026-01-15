package postgres

import (
	"context"
	"fmt"
	"identity/domain"
	"time"

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

func (r *PgRepository) Create(ctx context.Context, email, password string) (string, error) {
	var id string
	query := `INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id`
	err := r.db.GetContext(ctx, &id, query, email, password)
	return id, err
}

func (r *PgRepository) EnableTwoFactor(ctx context.Context, id, secret string) error {
	query := `UPDATE users SET two_factor_secret = $1 WHERE id = $2`
	_, err := r.db.ExecContext(ctx, query, secret, id)
	return err
}

func (r *PgRepository) DisableTwoFactor(ctx context.Context, id string) error {
	query := `UPDATE users SET two_factor_enabled = FALSE, two_factor_secret = NULL, two_factor_verified = FALSE WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *PgRepository) MarkTwoFactorVerified(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, "UPDATE users SET two_factor_verified = TRUE, two_factor_enabled = true WHERE id = $1", id)
	return err
}

func (r *PgRepository) SetRecoveryCodes(ctx context.Context, id, codes string) error {
	_, err := r.db.ExecContext(ctx, "UPDATE users SET two_factor_recovery_codes = $1 WHERE id = $2", codes, id)
	return err
}

func (r *PgRepository) FindRefreshToken(ctx context.Context, token string) (*domain.RefreshToken, error) {
	var refreshToken domain.RefreshToken
	err := r.db.GetContext(ctx, &refreshToken, "SELECT * FROM user_refresh_tokens WHERE token = $1", token)
	if err != nil {
		return nil, err
	}
	return &refreshToken, nil
}

func (r *PgRepository) ValidateAccessToken(ctx context.Context, token string) (*domain.AccessToken, error) {
	var accessToken domain.AccessToken
	query := `
		SELECT * FROM user_access_tokens
		WHERE token = $1
		AND revoked_at IS NULL
		AND expires_at > NOW()
	`
	err := r.db.GetContext(ctx, &accessToken, query, token)
	if err != nil {
		return nil, err
	}
	return &accessToken, nil
}

func (r *PgRepository) CreateAccessToken(ctx context.Context, user *domain.User, token string, usedAt time.Time, expiresAt time.Time) error {
	query := `INSERT INTO user_access_tokens (user_id, token, used_at, expires_at) VALUES ($1, $2, $3, $4)`
	_, err := r.db.ExecContext(ctx, query, user.ID, token, usedAt, expiresAt)
	if err != nil {
		return err
	}

	return nil
}

func (r *PgRepository) CreateRefreshToken(ctx context.Context, user *domain.User, token string, usedAt time.Time, expiresAt time.Time) error {
	query := `INSERT INTO user_refresh_tokens (user_id, token, used_at, expires_at) VALUES ($1, $2, $3, $4)`
	_, err := r.db.ExecContext(ctx, query, user.ID, token, usedAt, expiresAt)
	if err != nil {
		return err
	}

	return nil
}
