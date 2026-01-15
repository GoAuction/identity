package app

import (
	"context"
	"database/sql"
	"errors"
	"identity/pkg/jwt"
	"strings"
	"time"

	"identity/pkg/httperror"
)

type LoginHandler struct {
	repository Repository
}

type LoginRequest struct {
	Email    string `json:"email" param:"email"`
	Password string `json:"password" param:"password"`
}

type LoginResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

func NewLoginHandler(repository Repository) *LoginHandler {
	return &LoginHandler{
		repository: repository,
	}
}

func (h *LoginHandler) Handle(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
	req.Email = strings.TrimSpace(req.Email)
	req.Password = strings.TrimSpace(req.Password)

	if req.Email == "" || req.Password == "" {
		return nil, httperror.BadRequest(
			"identity.login.invalid_payload",
			"Email and password fields are required",
			nil,
		)
	}

	user, err := h.repository.FindByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, httperror.Unauthorized(
				"identity.login.invalid_credentials",
				"Invalid email or password",
				nil,
			)
		}

		return nil, httperror.InternalServerError(
			"identity.login.lookup_failed",
			"Invalid user",
			[]string{
				err.Error(),
			},
		)
	}

	if !user.ValidatePassword(req.Password) {
		return nil, httperror.Unauthorized(
			"identity.login.invalid_credentials",
			"Invalid email or password",
			nil,
		)
	}

	if user.TwoFactorEnabled && user.TwoFactorVerified {
		tfaJwt, err := jwt.GenerateToken(user)

		if err != nil {
			return nil, httperror.InternalServerError(
				"identity.login.token_generation_failed",
				"Failed to generate token",
				nil,
			)
		}

		return nil, httperror.Accepted(
			"identity.login.accepted",
			"Request accepted. Verify otp",
			struct {
				Jwt       string `json:"jwt"`
				ExpiresIn int64  `json:"expires_at"`
			}{
				Jwt:       tfaJwt,
				ExpiresIn: time.Now().Add(time.Hour).Unix(),
			},
		)
	}

	token, err := jwt.GenerateToken(user)
	if err != nil {
		return nil, httperror.InternalServerError(
			"identity.login.token_generation_failed",
			"Failed to generate token",
			nil,
		)
	}

	refreshToken, err := jwt.GenerateRefreshToken(user)
	if err != nil {
		return nil, httperror.InternalServerError(
			"identity.login.token_generation_failed",
			"Failed to generate token",
			nil,
		)
	}

	err = h.repository.CreateAccessToken(ctx, user, token, time.Now(), time.Now().Add(jwt.AccessTokenDuration))
	if err != nil {
		return nil, httperror.InternalServerError(
			"identity.login.token_generation_failed",
			"Failed to generate token",
			[]string{err.Error()},
		)
	}

	err = h.repository.CreateRefreshToken(ctx, user, refreshToken, time.Now(), time.Now().Add(jwt.RefreshTokenDuration))
	if err != nil {
		return nil, httperror.InternalServerError(
			"identity.login.token_generation_failed",
			"Failed to generate token",
			[]string{err.Error()},
		)
	}

	return &LoginResponse{
		Token:        token,
		RefreshToken: refreshToken,
	}, nil
}
