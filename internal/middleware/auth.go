package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/shubhkasyap1/go-backend-task/internal/auth"
	"github.com/shubhkasyap1/go-backend-task/internal/user"
)

const (
	SessionKey = "session"
	UserKey    = "user"
)

func Auth(
	sessionRepo *auth.SessionRepository,
	userRepo *user.Repository,
) gin.HandlerFunc {

	return func(c *gin.Context) {

		authHeader := c.GetHeader("Authorization")

		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "authorization header is required",
			})
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)

		if len(parts) != 2 ||
			!strings.EqualFold(parts[0], "Bearer") ||
			parts[1] == "" {

			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid authorization header",
			})
			c.Abort()
			return
		}

		sessionID := parts[1]

		session, err := sessionRepo.FindValid(
			c.Request.Context(),
			sessionID,
		)

		if err != nil {
			if errors.Is(err, auth.ErrSessionNotFound) {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": "invalid or expired session",
				})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "failed to validate session",
				})
			}

			c.Abort()
			return
		}

		foundUser, err := userRepo.FindByID(
			c.Request.Context(),
			session.UserID,
		)

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "user not found",
			})
			c.Abort()
			return
		}

		c.Set(SessionKey, session)
		c.Set(UserKey, foundUser)

		c.Next()
	}
}
