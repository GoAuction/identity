package identity

import (
	"auction/pkg/httperror"
	"auction/pkg/totp"
	"context"
)

type EnableTwoFactorHandler struct {
	repository Repository
}

type EnableTwoFactorRequest struct {
}

type EnableTwoFactorResponse struct {
	TotpUrl string `json:"totp_url"`
}

func NewEnableTwoFactorHandler(repository Repository) *EnableTwoFactorHandler {
	return &EnableTwoFactorHandler{
		repository: repository,
	}
}

func (e EnableTwoFactorHandler) Handle(ctx context.Context, _ *EnableTwoFactorRequest) (*EnableTwoFactorResponse, error) {
	val := ctx.Value("UserID")
	userID := val.(string)

	user, err := e.repository.FindByID(userID)
	if err != nil {
		return nil, httperror.NotFound(
			"identity.enable_two_factor.invalid_user_id",
			"Invalid user id",
			nil,
		)
	}

	var secret string
	if user.TwoFactorEnabled {
		secret = user.TwoFactorSecret
	}else {
		secret = totp.GenerateTwoFactorSecret()
	}

	err = e.repository.EnableTwoFactor(ctx, userID, secret)
	if err != nil {
		return nil, httperror.InternalServerError(
			"identity.enable_two_factor.internal_server_error",
			"Internal server error",
			nil,
		)
	}

	totpUrl := totp.BuildUrl(secret, user.Email, "Auction Identity")

	return &EnableTwoFactorResponse{
		TotpUrl: totpUrl,
	}, nil
}