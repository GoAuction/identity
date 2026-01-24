package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"identity/pkg/httperror"
)

type ChangePasswordHandler struct {
	repository Repository
}

type ChangePasswordRequest struct {
	OldPassword          string `json:"old_password"`
	NewPassword          string `json:"password"`
	PasswordConfirmation string `json:"password_confirmation"`
}

type ChangePasswordResponse struct {
	ID                string `json:"id"`
	Email             string `json:"email"`
	TwoFactorVerified bool   `json:"two_factor_verified"`
	TwoFactorEnabled  bool   `json:"two_factor_enabled"`
}

func NewChangePasswordHandler(repository Repository) *ChangePasswordHandler {
	return &ChangePasswordHandler{
		repository: repository,
	}
}

func (e ChangePasswordHandler) Handle(ctx context.Context, request *ChangePasswordRequest) (*ChangePasswordResponse, error) {
	userID := ctx.Value("UserID").(string)

	user, err := e.repository.FindByID(ctx, userID)
	if err != nil {
		return nil, httperror.NotFound(
			"identity.change_password.invalid_user_id",
			"Invalid user id",
			nil,
		)
	}

	if request.NewPassword != request.PasswordConfirmation {
		return nil, httperror.BadRequest(
			"identity.change_password.password_mismatch",
			"Password mismatch",
			nil,
		)
	}

	if request.OldPassword == request.NewPassword {
		return nil, httperror.BadRequest(
			"identity.change_password.password_same",
			"Password same",
			nil,
		)
	}

	oldPasswordHash := sha256.Sum256([]byte(request.OldPassword))
	hashedOldPassword := hex.EncodeToString(oldPasswordHash[:])

	if hashedOldPassword != user.Password {
		return nil, httperror.BadRequest(
			"identity.change_password.invalid_old_password",
			"Invalid old password",
			nil,
		)
	}

	newPasswordHash := sha256.Sum256([]byte(request.NewPassword))
	hashedNewPassword := hex.EncodeToString(newPasswordHash[:])

	err = e.repository.ChangePassword(ctx, userID, hashedNewPassword)
	if err != nil {
		return nil, httperror.InternalServerError(
			"identity.change_password.internal_server_error",
			"Internal server error",
			nil,
		)
	}

	return &ChangePasswordResponse{
		ID:                userID,
		Email:             user.Email,
		TwoFactorVerified: user.TwoFactorVerified,
		TwoFactorEnabled:  user.TwoFactorEnabled,
	}, nil
}
