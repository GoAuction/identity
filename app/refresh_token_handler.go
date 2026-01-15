package app

import (
	"context"
	"identity/pkg/httperror"
	"identity/pkg/jwt"
	"time"
)

type RefreshTokenRequest struct {
	Token string `json:"token"`
}

type RefreshTokenResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshTokenHandler struct {
	repository Repository
}

func NewRefreshTokenHandler(repository Repository) *RefreshTokenHandler {
	return &RefreshTokenHandler{
		repository: repository,
	}
}

func (h *RefreshTokenHandler) Handle(ctx context.Context, request *RefreshTokenRequest) (*RefreshTokenResponse, error) {
	refreshToken, err := h.repository.FindRefreshToken(ctx, request.Token)
	if err != nil {
		return nil, httperror.InternalServerError(
			"identity.login.token_verification_failed",
			"Failed to verify token",
			nil,
		)
	}

	if refreshToken.ExpiresAt.Before(time.Now()) {
		return nil, httperror.Unauthorized(
			"identity.login.token_expired",
			"Token has expired",
			nil,
		)
	}

	user, err := h.repository.FindByID(ctx, refreshToken.UserID)
	if err != nil {
		return nil, httperror.InternalServerError(
			"identity.login.user_not_found",
			"Failed to find user",
			nil,
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

	newRefreshToken, err := jwt.GenerateRefreshToken(user)
	if err != nil {
		return nil, httperror.InternalServerError(
			"identity.login.token_generation_failed",
			"Failed to generate token",
			nil,
		)
	}

	// Yeni access token'ı database'e kaydet
	err = h.repository.CreateAccessToken(ctx, user, token, time.Now(), time.Now().Add(jwt.AccessTokenDuration))
	if err != nil {
		return nil, httperror.InternalServerError(
			"identity.refresh_token.token_save_failed",
			"Failed to save access token",
			[]string{err.Error()},
		)
	}

	// Yeni refresh token'ı database'e kaydet
	err = h.repository.CreateRefreshToken(ctx, user, newRefreshToken, time.Now(), time.Now().Add(jwt.RefreshTokenDuration))
	if err != nil {
		return nil, httperror.InternalServerError(
			"identity.refresh_token.token_save_failed",
			"Failed to save refresh token",
			[]string{err.Error()},
		)
	}

	return &RefreshTokenResponse{
		Token:        token,
		RefreshToken: newRefreshToken,
	}, nil
}
