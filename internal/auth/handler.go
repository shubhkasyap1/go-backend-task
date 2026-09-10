package auth

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/shubhkasyap1/go-backend-task/internal/config"
	"github.com/shubhkasyap1/go-backend-task/internal/user"
)

type Handler struct {
	service     *Service
	sessionRepo *SessionRepository
}

func NewHandler(
	service *Service,
	sessionRepo *SessionRepository,
) *Handler {
	return &Handler{
		service:     service,
		sessionRepo: sessionRepo,
	}
}

func (h *Handler) Register(c *gin.Context) {
	var request user.RegisterRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "username and password are required",
		})
		return
	}

	newUser, err := h.service.Register(
		c.Request.Context(),
		request.Username,
		request.Password,
	)

	if err != nil {
		if errors.Is(err, user.ErrUsernameExists) {
			c.JSON(http.StatusConflict, gin.H{
				"error": "username already exists",
			})
			return
		}

		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "user registered successfully",
		"user": gin.H{
			"id":         newUser.ID,
			"username":   newUser.Username,
			"created_at": newUser.CreatedAt,
		},
	})
}

func (h *Handler) Login(c *gin.Context) {
	var request user.LoginRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "username and password are required",
		})
		return
	}

	cfg := config.Load()

	foundUser, session, err := h.service.Login(
		c.Request.Context(),
		request.Username,
		request.Password,
		cfg.MaxLoginAttempts,
		cfg.LockoutMinutes,
		cfg.SessionTimeoutMinutes,
	)

	if err != nil {
		switch {
		case errors.Is(err, ErrAccountLocked):
			c.JSON(http.StatusLocked, gin.H{
				"error": "account is temporarily locked",
			})

		case errors.Is(err, ErrInvalidCredentials):
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid username or password",
			})

		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "login failed",
			})
		}

		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "login successful",
		"session": gin.H{
			"id":         session.ID,
			"expires_at": session.ExpiresAt,
		},
		"user": gin.H{
			"id":            foundUser.ID,
			"username":      foundUser.Username,
			"mfa_enabled":   foundUser.MFAEnabled,
			"last_login_at": foundUser.LastLoginAt,
			"created_at":    foundUser.CreatedAt,
		},
	})
}

func (h *Handler) Me(c *gin.Context) {
	value, exists := c.Get("user")

	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "not authenticated",
		})
		return
	}

	foundUser, ok := value.(*user.User)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "invalid user data",
		})
		return
	}

	sessionValue, exists := c.Get("session")

	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "session data not found",
		})
		return
	}

	session, ok := sessionValue.(*Session)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "invalid session data",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"username":          foundUser.Username,
		"registration_date": foundUser.CreatedAt,
		"mfa_enabled":       foundUser.MFAEnabled,
		"session_expires":   session.ExpiresAt,
		"last_login":        foundUser.LastLoginAt,
	})
}

func (h *Handler) Logout(c *gin.Context) {
	sessionValue, exists := c.Get("session")

	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "not authenticated",
		})
		return
	}

	session, ok := sessionValue.(*Session)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "invalid session data",
		})
		return
	}

	if err := h.sessionRepo.Delete(
		c.Request.Context(),
		session.ID,
	); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to logout",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "logout successful",
	})
}
