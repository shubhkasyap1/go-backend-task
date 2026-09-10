package user

import "time"

type User struct {
	ID                  string     `json:"id"`
	Username            string     `json:"username"`
	PasswordHash        string     `json:"-"`
	MFAEnabled          bool       `json:"mfa_enabled"`
	MFASecret           *string    `json:"-"`
	FailedLoginAttempts int        `json:"failed_login_attempts"`
	LockedUntil         *time.Time `json:"locked_until"`
	LastLoginAt         *time.Time `json:"last_login_at"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Password string `json:"password" binding:"required,min=8"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type TOTPRequest struct {
	Code string `json:"code" binding:"required,len=6"`
}
