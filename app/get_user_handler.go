package app

import (
	"context"
	"identity/pkg/httperror"
)

type GetUserHandler struct {
	repository Repository
}

type GetUserRequest struct {
}

type GetUserResponse struct {
	ID                string `json:"id"`
	Email             string `json:"email"`
	TwoFactorVerified bool   `json:"two_factor_verified"`
	TwoFactorEnabled  bool   `json:"two_factor_enabled"`
}

func NewGetUserHandler(repository Repository) *GetUserHandler {
	return &GetUserHandler{
		repository: repository,
	}
}

func (g *GetUserHandler) Handle(ctx context.Context, _ *GetUserRequest) (*GetUserResponse, error) {
	val := ctx.Value("UserID")
	userID := val.(string)

	user, err := g.repository.FindByID(ctx, userID)
	if err != nil {
		return nil, httperror.NotFound("identity.get_user.not_found", "User not found", nil)
	}

	return &GetUserResponse{
		ID:                user.ID,
		Email:             user.Email,
		TwoFactorVerified: user.TwoFactorVerified,
		TwoFactorEnabled:  user.TwoFactorEnabled,
	}, nil
}
