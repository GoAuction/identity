package identity

import (
	"auction/pkg/httperror"
	"context"
)

type DisableTwoFactorHandler struct {
	repository Repository
}

type DisableTwoFactorRequest struct {
}

type DisableTwoFactorResponse struct {
}

func NewDisableTwoFactorHandler(repository Repository) *DisableTwoFactorHandler {
	return &DisableTwoFactorHandler{
		repository: repository,
	}
}

func (e DisableTwoFactorHandler) Handle(ctx context.Context, _ *DisableTwoFactorRequest) (*DisableTwoFactorResponse, error) {
	val := ctx.Value("UserID")
	userID := val.(string)

	_, err := e.repository.FindByID(userID)
	if err != nil {
		return nil, httperror.NotFound(
			"identity.enable_two_factor.invalid_user_id",
			"Invalid user id",
			nil,
		)
	}

	err = e.repository.DisableTwoFactor(ctx, userID)
	if err != nil {
		return nil, httperror.InternalServerError(
			"identity.enable_two_factor.internal_server_error",
			"Internal server error",
			nil,
		)
	}

	return nil, httperror.NoContent("identity.enable_two_factor.no_content", "No content", nil)
}