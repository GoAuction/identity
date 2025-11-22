package identity

import (
	"auction/pkg/httperror"
	"auction/pkg/totp"
	"context"
	"encoding/json"
	"strings"
)

type VerifyTwoFactorHandler struct {
	repository Repository
}

type VerifyTwoFactorRequest struct {
	Code string `json:"code"`
}

type VerifyTwoFactorResponse struct {
	RecoveryCodes []string `json:"recovery_codes"`
}

func NewVerifyTwoFactorHandler(repository Repository) *VerifyTwoFactorHandler {
	return &VerifyTwoFactorHandler{
		repository: repository,
	}
}

func (v VerifyTwoFactorHandler) Handle(ctx context.Context, req *VerifyTwoFactorRequest) (*VerifyTwoFactorResponse, error) {
	req.Code = strings.TrimSpace(req.Code)

	val := ctx.Value("UserID")
	userID := val.(string)

	user, err := v.repository.FindByID(userID)
	if err != nil {
		return nil, httperror.NotFound("identity.two_factor_challenge.not_found", "User not found", nil)
	}

	passed := totp.VerifyOTP(user.TwoFactorSecret, req.Code, 0, 0, 0)
	if !passed {
		return nil, httperror.BadRequest("identity.verify_two_factor.invalid_code", "Invalid code", nil)
	}

	err = v.repository.MarkTwoFactorVerified(ctx, user.ID)
	if err != nil {
		return nil, httperror.InternalServerError("identity.verify_two_factor.server_error", "Internal server error", nil)
	}

	recoveryCodes := totp.GenerateRecoveryCodes(10)
	rawRecoveryCodes, err := json.Marshal(recoveryCodes)
	if err != nil {
		return nil, httperror.InternalServerError("identity.verify_two_factor.server_error", "Internal server error", nil)
	}

	err = v.repository.SetRecoveryCodes(ctx, user.ID, string(rawRecoveryCodes))
	if err != nil {
		return nil, httperror.InternalServerError("identity.verify_two_factor.server_error", "Internal server error", nil)
	}

	return &VerifyTwoFactorResponse{
		RecoveryCodes: recoveryCodes,
	}, nil
}