package middleware

import (
	"context"
	"database/sql"
	identity "identity/app"
	"identity/pkg/httperror"
	"strings"

	jwtPkg "identity/pkg/jwt"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

func NewBearerAuthMiddleware(secret string, repo identity.Repository) fiber.Handler {
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

		// JWT formatını ve imzasını doğrula
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

		// Token'ı database'de doğrula
		ctx := c.UserContext()
		if ctx == nil {
			ctx = context.Background()
		}

		accessToken, err := repo.ValidateAccessToken(ctx, tokenString)
		if err != nil {
			if err == sql.ErrNoRows {
				zap.L().Warn("Token not found in database or revoked/expired",
					zap.String("userId", claims.Subject),
					zap.Error(err))
				return unauthorized(c)
			}
			zap.L().Error("Failed to validate access token",
				zap.String("userId", claims.Subject),
				zap.Error(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"code":    "identity.auth.validation_error",
				"message": "Failed to validate token",
			})
		}

		// Token sahibinin JWT'deki user ID ile eşleşip eşleşmediğini kontrol et
		if accessToken.UserID != claims.Subject {
			zap.L().Warn("Token user ID mismatch",
				zap.String("tokenUserId", accessToken.UserID),
				zap.String("claimsUserId", claims.Subject))
			return unauthorized(c)
		}

		userCtx := context.WithValue(ctx, "UserID", claims.Subject)
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
