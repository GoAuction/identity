package jwt

import (
	"identity/pkg/config"
	"time"

	"identity/domain"

	jwtPkg "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var appConfig = config.Read()

type Claims struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	jwtPkg.RegisteredClaims
}

const (
	AccessTokenDuration  = 1 * time.Hour
	RefreshTokenDuration = 30 * 24 * time.Hour
)

func GenerateToken(u *domain.User) (string, error) {
	token := jwtPkg.NewWithClaims(jwtPkg.SigningMethodHS256, Payload(u))

	secret := []byte(appConfig.JWTSecret)

	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func GenerateRefreshToken(u *domain.User) (string, error) {
	token := jwtPkg.NewWithClaims(jwtPkg.SigningMethodHS256, RefreshPayload(u))

	secret := []byte(appConfig.JWTSecret)

	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func Payload(u *domain.User) Claims {
	return Claims{
		Name:  u.Name,
		Email: u.Email,
		RegisteredClaims: jwtPkg.RegisteredClaims{
			Issuer:    "Identity",
			Subject:   u.ID,
			Audience:  jwtPkg.ClaimStrings{"api"},
			ExpiresAt: jwtPkg.NewNumericDate(time.Now().Add(AccessTokenDuration)),
			NotBefore: jwtPkg.NewNumericDate(time.Now()),
			IssuedAt:  jwtPkg.NewNumericDate(time.Now()),
			ID:        uuid.New().String(),
		},
	}
}

func RefreshPayload(u *domain.User) Claims {
	return Claims{
		Name:  u.Name,
		Email: u.Email,
		RegisteredClaims: jwtPkg.RegisteredClaims{
			Issuer:    "Identity",
			Subject:   u.ID,
			Audience:  jwtPkg.ClaimStrings{"api"},
			ExpiresAt: jwtPkg.NewNumericDate(time.Now().Add(RefreshTokenDuration)),
			NotBefore: jwtPkg.NewNumericDate(time.Now()),
			IssuedAt:  jwtPkg.NewNumericDate(time.Now()),
			ID:        uuid.New().String(),
		},
	}
}

func Decode(jwt string) (*Claims, error) {
	tokenSecret := []byte(appConfig.JWTSecret)

	parsedToken, err := jwtPkg.ParseWithClaims(jwt, &Claims{}, func(token *jwtPkg.Token) (any, error) {
		if _, ok := token.Method.(*jwtPkg.SigningMethodHMAC); !ok {
			return nil, jwtPkg.ErrSignatureInvalid
		}
		return tokenSecret, nil
	})

	if err != nil || parsedToken == nil || !parsedToken.Valid {
		return &Claims{}, err
	}

	claims, ok := parsedToken.Claims.(*Claims)
	if !ok || claims.Subject == "" {
		return &Claims{}, err
	}

	return claims, nil
}
