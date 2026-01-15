package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"identity/domain"
	"identity/pkg/events"
	"identity/pkg/httperror"

	"github.com/lib/pq"
	"go.uber.org/zap"
)

type RegisterHandler struct {
	repository Repository
	publisher  events.Publisher
}

func NewRegisterHandler(repository Repository, publisher events.Publisher) *RegisterHandler {
	return &RegisterHandler{
		repository: repository,
		publisher:  publisher,
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

	id, err := h.repository.Create(ctx, req.Email, hashedPassword)
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

	h.publishEvent(ctx, domain.User{
		ID:    id,
		Email: req.Email,
		Name:  req.Name,
	})

	return &RegisterResponse{ID: id, Email: req.Email, Name: req.Name}, nil
}

func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "23505"
	}
	return false
}

func (h RegisterHandler) publishEvent(ctx context.Context, user domain.User) {
	eventPayload := events.UserRegisteredPayload{
		Email:     user.Email,
		Name:      user.Name,
		UserID:    user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}

	headers := events.Headers{
		TraceID:       events.GenerateTraceID(),
		CorrelationID: events.GenerateCorrelationID(),
		Service:       "identity",
	}

	event := events.NewEvent(
		events.UserRegisteredEvent,
		events.EventVersionV1,
		eventPayload,
		headers,
	)

	if err := h.publisher.Publish(ctx, events.IdentityExchange, event, headers); err != nil {
		zap.L().Error("Failed to publish identity.registered event",
			zap.String("userID", user.ID),
			zap.Error(err),
		)
	}
}
