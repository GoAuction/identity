package app

import (
	"context"
	"identity/domain"
	"time"
)

type Repository interface {
	FindByID(ctx context.Context, id string) (*domain.User, error)
	FindByEmail(ctx context.Context, email string) (*domain.User, error)
	Create(ctx context.Context, email string, password string) (string, error)
	EnableTwoFactor(ctx context.Context, id string, twoFactorSecret string) error
	DisableTwoFactor(ctx context.Context, id string) error
	MarkTwoFactorVerified(ctx context.Context, id string) error
	SetRecoveryCodes(ctx context.Context, id string, recoveryCodes string) error
	FindRefreshToken(ctx context.Context, token string) (*domain.RefreshToken, error)
	ValidateAccessToken(ctx context.Context, token string) (*domain.AccessToken, error)
	CreateAccessToken(ctx context.Context, user *domain.User, token string, usedAt time.Time, expiresAt time.Time) error
	CreateRefreshToken(ctx context.Context, user *domain.User, token string, usedAt time.Time, expiresAt time.Time) error
	ChangePassword(ctx context.Context, id string, password string) error
}
