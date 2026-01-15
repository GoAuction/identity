package events

import (
	"time"
)

const (
	IdentityDomain   = "identity"
	IdentityExchange = "identity.user"
)

const (
	UserRegisteredEvent = "user.registered"
)

const (
	EventVersionV1 = "v1"
)

type UserRegisteredPayload struct {
	UserID    string
	Name      string
	Email     string
	CreatedAt time.Time
	UpdatedAt time.Time
}
