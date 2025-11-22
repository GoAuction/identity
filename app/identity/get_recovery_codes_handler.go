package identity

import (
	"auction/pkg/httperror"
	"context"
	"encoding/json"
)

type GetRecoveryCodesHandler struct {
	repository Repository
}

type GetRecoveryCodesRequest struct {
}

type GetRecoveryCodesResponse struct {
	RecoveryCodes []string `json:"recovery_codes"`
}

func NewGetRecoveryCodesHandler(repository Repository) *GetRecoveryCodesHandler {
	return &GetRecoveryCodesHandler{
		repository: repository,
	}
}

func (g GetRecoveryCodesHandler) Handle(ctx context.Context, _ *GetRecoveryCodesRequest) (*GetRecoveryCodesResponse, error) {
	val := ctx.Value("UserID")
	userID := val.(string)

	user, err := g.repository.FindByID(userID)
	if err != nil {
		return nil, httperror.NotFound("identity.get_recovery_codes.not_found", "User not found", nil)
	}

	var recoveryCodes []string

	if user.TwoFactorRecoveryCodes == "" {
		user.TwoFactorRecoveryCodes = "[]"
	}

	err = json.Unmarshal([]byte(user.TwoFactorRecoveryCodes), &recoveryCodes)
	if err != nil {
		return nil, httperror.InternalServerError(
			"identity.get_recovery_codes.server_error",
			"Internal server error",
			nil,
		)
	}

	return &GetRecoveryCodesResponse{
		RecoveryCodes: recoveryCodes,
	}, nil
}