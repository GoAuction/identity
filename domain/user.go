package domain

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"time"
)

type User struct {
	ID                     string         `json:"id" db:"id"`
	Email                  string         `json:"email" db:"email"`
	Password               string         `json:"password" db:"password"`
	Name                   string         `json:"name" db:"name"`
	TwoFactorSecret        sql.NullString `json:"two_factor_secret" db:"two_factor_secret"`
	TwoFactorVerified      bool           `json:"two_factor_verified" db:"two_factor_verified"`
	TwoFactorEnabled       bool           `json:"two_factor_enabled" db:"two_factor_enabled"`
	TwoFactorRecoveryCodes sql.NullString `json:"two_factor_recovery_codes" db:"two_factor_recovery_codes"`
	CreatedAt              time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt              time.Time      `json:"updated_at" db:"updated_at"`
}

func (u *User) ValidatePassword(password string) bool {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:]) == u.Password
}