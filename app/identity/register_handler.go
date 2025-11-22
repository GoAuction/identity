package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"auction/pkg/httperror"

	"github.com/lib/pq"
)

type RegisterHandler struct {
	repository Repository
}

func NewRegisterHandler(repository Repository) *RegisterHandler {
	return &RegisterHandler{
		repository: repository,
	}
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type RegisterResponse struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

func (h *RegisterHandler) Handle(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	req.Email = strings.TrimSpace(req.Email)
	req.Password = strings.TrimSpace(req.Password)
	req.Name = strings.TrimSpace(req.Name)

	hash := sha256.Sum256([]byte(req.Password))
	hashedPassword := hex.EncodeToString(hash[:])

	if req.Email == "" {
		return nil, httperror.BadRequest("identity.register.email_required", "Email field is required", nil)
	}

	if req.Password == "" {
		return nil, httperror.BadRequest("identity.register.password_required", "Password field is required", nil)
	}

	if req.Name == "" {
		return nil, httperror.BadRequest("identity.register.name_required", "Name field is required", nil)
	}

	id, err := h.repository.Create(ctx, req.Email, hashedPassword, req.Name)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, httperror.Conflict(
				"identity.register.email_exists",
				"Email already exists",
				nil,
			)
		}

		return nil, httperror.InternalServerError(
			"identity.register.create_failed",
			"An error occurred during registration",
			nil,
		)
	}
	return &RegisterResponse{ID: id, Email: req.Email, Name: req.Name}, nil
}

func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "23505"
	}
	return false
}
