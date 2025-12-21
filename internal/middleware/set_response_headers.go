package middleware

import (
	"github.com/gofiber/fiber/v2"
)

func SetResponseHeadersMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		err := c.Next()

		if userID, ok := c.UserContext().Value("UserID").(string); ok && userID != "" {
			c.Set("User-ID", userID)
		}

		if userEmail, ok := c.UserContext().Value("UserEmail").(string); ok && userEmail != "" {
			c.Set("User-Email", userEmail)
		}

		if jwt, ok := c.UserContext().Value("Jwt").(string); ok && jwt != "" {
			c.Set("Authorization", "Bearer "+jwt)
		}

		if userName, ok := c.UserContext().Value("UserName").(string); ok && userName != "" {
			c.Set("User-Name", userName)
		}

		return err
	}
}
