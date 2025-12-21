package identity

import (
	"auction/pkg/httperror"
	"auction/pkg/jwt"
	"context"
)

type ValidateHandler struct {
	repository Repository
}

type ValidateHandlerRequest struct {
}

type ValidateHandlerResponse struct {
	Claims jwt.Claims `json:"claims"`
}

func NewValidateHandler(repository Repository) *ValidateHandler {
	return &ValidateHandler{
		repository: repository,
	}
}

func (g ValidateHandler) Handle(ctx context.Context, _ *ValidateHandlerRequest) (*ValidateHandlerResponse, error) {
	val := ctx.Value("Jwt")
	jwtString := val.(string)

	claims, err := jwt.Decode(jwtString)
	if err != nil {
		return nil, httperror.InternalServerError("identity.validate.server_error", "Internal server error", nil)
	}

	ctx = context.WithValue(ctx, "UserName", claims.Name)

	return &ValidateHandlerResponse{
		Claims: *claims,
	}, nil
}
