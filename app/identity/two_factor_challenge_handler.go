package identity

import (
	"auction/pkg/httperror"
	"auction/pkg/jwt"
	"context"
	"strings"
	"auction/pkg/totp"
)

type TwoFactorChallengeHandler struct {
	repository Repository
}

type TwoFactorChallengeRequest struct {
	Code string `json:"code"`
	Jwt string `json:"jwt"`
}

type TwoFactorChallengeResponse struct {
	Token string `json:"token"`
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

	user, err := t.repository.FindByID(claims.Subject)
	if err != nil {
		return nil, httperror.NotFound("identity.two_factor_challenge.not_found", "User not found", nil)
	}

	if !totp.VerifyOTP(user.TwoFactorSecret, req.Code, 0,0,0) {
		return nil, httperror.BadRequest("identity.two_factor_challenge.invalid_code", "Invalid code", nil)
	}

	token, err := jwt.CreateToken(user)
	if err != nil {
		return nil, httperror.InternalServerError("identity.two_factor_challenge.internal_server_error", "Internal server error", nil)
	}

	return &TwoFactorChallengeResponse{
		Token: token,
	}, nil
}
