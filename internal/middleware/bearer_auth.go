package middleware

import (
	"auction/pkg/httperror"
	"context"
	"strings"

	jwtPkg "auction/pkg/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

func NewBearerAuthMiddleware(secret string) fiber.Handler {
	tokenSecret := []byte(secret)

	return func(c *fiber.Ctx) error {
		authHeader := strings.TrimSpace(c.Get("Authorization"))
		if authHeader == "" {
			return unauthorized(c)
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
			return unauthorized(c)
		}

		tokenString := strings.TrimSpace(parts[1])

		parsedToken, err := jwt.ParseWithClaims(tokenString, &jwtPkg.Claims{}, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return tokenSecret, nil
		})
		if err != nil || parsedToken == nil || !parsedToken.Valid {
			return unauthorized(c)
		}

		claims, ok := parsedToken.Claims.(*jwtPkg.Claims)
		if !ok || claims.Subject == "" {
			return unauthorized(c)
		}

		userCtx := c.UserContext()
		if userCtx == nil {
			userCtx = context.Background()
		}

		userCtx = context.WithValue(userCtx, "UserID", claims.Subject)
		userCtx = context.WithValue(userCtx, "UserEmail", claims.Email)
		userCtx = context.WithValue(userCtx, "Jwt", tokenString)

		c.SetUserContext(userCtx)
		return c.Next()
	}
}

func unauthorized(c *fiber.Ctx) error {
	err := httperror.Unauthorized(
		"identity.auth.unauthorized",
		"Authorization token missing or invalid",
		nil,
	)

	return c.Status(err.Status).JSON(fiber.Map{
		"code":    err.Code,
		"message": err.Message,
	})
}
