package app

import (
	"context"
	"identity/pkg/httperror"
	"identity/pkg/jwt"
	"identity/pkg/totp"
	"strings"
	"time"
)

type TwoFactorChallengeHandler struct {
	repository Repository
}

type TwoFactorChallengeRequest struct {
	Code string `json:"code"`
	Jwt  string `json:"jwt"`
}

type TwoFactorChallengeResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

func NewTwoFactorChallengeHandler(repository Repository) *TwoFactorChallengeHandler {
	return &TwoFactorChallengeHandler{
		repository: repository,
	}
}

func (t TwoFactorChallengeHandler) Handle(ctx context.Context, req *TwoFactorChallengeRequest) (*TwoFactorChallengeResponse, error) {
	req.Code = strings.TrimSpace(req.Code)
	req.Jwt = strings.TrimSpace(req.Jwt)

	claims, err := jwt.Decode(req.Jwt)
	if err != nil {
		return nil, httperror.InternalServerError("identity.two_factor_challenge.internal_server_error", "Internal server error", nil)
	}

	user, err := t.repository.FindByID(ctx, claims.Subject)
	if err != nil {
		return nil, httperror.NotFound("identity.two_factor_challenge.not_found", "User not found", nil)
	}

	if !user.TwoFactorSecret.Valid || !totp.VerifyOTP(user.TwoFactorSecret.String, req.Code, 0, 0, 0) {
		return nil, httperror.BadRequest("identity.two_factor_challenge.invalid_code", "Invalid code", nil)
	}

	token, err := jwt.GenerateToken(user)
	if err != nil {
		return nil, httperror.InternalServerError("identity.two_factor_challenge.internal_server_error", "Internal server error", nil)
	}

	refreshToken, err := jwt.GenerateRefreshToken(user)
	if err != nil {
		return nil, httperror.InternalServerError("identity.two_factor_challenge.internal_server_error", "Internal server error", nil)
	}

	// Token'ı database'e kaydet
	err = t.repository.CreateAccessToken(ctx, user, token, time.Now(), time.Now().Add(jwt.AccessTokenDuration))
	if err != nil {
		return nil, httperror.InternalServerError(
			"identity.two_factor_challenge.token_save_failed",
			"Failed to save token",
			[]string{err.Error()},
		)
	}

	err = t.repository.CreateRefreshToken(ctx, user, refreshToken, time.Now(), time.Now().Add(jwt.RefreshTokenDuration))
	if err != nil {
		return nil, httperror.InternalServerError(
			"identity.two_factor_challenge.refresh_token_save_failed",
			"Failed to save refresh token",
			[]string{err.Error()},
		)
	}

	return &TwoFactorChallengeResponse{
		Token:        token,
		RefreshToken: refreshToken,
	}, nil
}
