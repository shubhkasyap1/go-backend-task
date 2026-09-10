package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"golang.org/x/crypto/bcrypt"

	"github.com/shubhkasyap1/go-backend-task/internal/user"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrAccountLocked      = errors.New("account is temporarily locked")
	ErrMFARequired        = errors.New("2FA code is required")
	ErrInvalidTOTP        = errors.New("invalid 2FA code")
)

type Service struct {
	userRepo    *user.Repository
	sessionRepo *SessionRepository
}

func NewService(
	userRepo *user.Repository,
	sessionRepo *SessionRepository,
) *Service {
	return &Service{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
	}
}

// Register creates a new user with a securely hashed password.
func (s *Service) Register(
	ctx context.Context,
	username string,
	password string,
) (*user.User, error) {

	username = strings.TrimSpace(username)

	if username == "" {
		return nil, errors.New("username is required")
	}

	if len(username) < 3 {
		return nil, errors.New("username must be at least 3 characters")
	}

	if len(username) > 50 {
		return nil, errors.New("username must not exceed 50 characters")
	}

	if len(password) < 8 {
		return nil, errors.New("password must be at least 8 characters")
	}

	passwordHash, err := HashPassword(password)
	if err != nil {
		return nil, errors.New("failed to secure password")
	}

	newUser, err := s.userRepo.Create(
		ctx,
		username,
		passwordHash,
	)
	if err != nil {
		return nil, err
	}

	return newUser, nil
}

// Login authenticates a user using username/password.
// If MFA is enabled, a valid TOTP code is also required.
func (s *Service) Login(
	ctx context.Context,
	username string,
	password string,
	totpCode string,
	maxLoginAttempts int,
	lockoutMinutes int,
	sessionTimeoutMinutes int,
) (*user.User, *Session, error) {

	username = strings.TrimSpace(username)
	totpCode = strings.TrimSpace(totpCode)

	// Find user.
	foundUser, err := s.userRepo.FindByUsername(
		ctx,
		username,
	)
	if err != nil {
		if errors.Is(err, user.ErrUserNotFound) {
			return nil, nil, ErrInvalidCredentials
		}

		return nil, nil, fmt.Errorf(
			"failed to find user: %w",
			err,
		)
	}

	// Check whether account is locked.
	if foundUser.LockedUntil != nil &&
		time.Now().Before(*foundUser.LockedUntil) {

		return nil, nil, ErrAccountLocked
	}

	// Verify password.
	if err := bcrypt.CompareHashAndPassword(
		[]byte(foundUser.PasswordHash),
		[]byte(password),
	); err != nil {

		attempts, err := s.userRepo.RecordFailedLogin(
			ctx,
			foundUser.ID,
		)
		if err != nil {
			return nil, nil, err
		}

		// Lock account after maximum failed attempts.
		if attempts >= maxLoginAttempts {

			lockUntil := time.Now().Add(
				time.Duration(lockoutMinutes) * time.Minute,
			)

			if err := s.userRepo.LockAccount(
				ctx,
				foundUser.ID,
				lockUntil,
			); err != nil {
				return nil, nil, err
			}

			return nil, nil, ErrAccountLocked
		}

		return nil, nil, ErrInvalidCredentials
	}

	// --------------------------------------------------
	// MFA CHECK
	// --------------------------------------------------

	// MFA disabled:
	// password authentication is enough.
	if foundUser.MFAEnabled {

		// MFA enabled but no code supplied.
		if totpCode == "" {
			return nil, nil, ErrMFARequired
		}

		// MFA enabled but secret is missing.
		if foundUser.MFASecret == nil ||
			*foundUser.MFASecret == "" {

			return nil, nil, errors.New(
				"MFA secret is not configured",
			)
		}

		// Validate TOTP code.
		if !ValidateTOTP(
			totpCode,
			*foundUser.MFASecret,
		) {
			return nil, nil, ErrInvalidTOTP
		}
	}

	// --------------------------------------------------
	// LOGIN SUCCESS
	// --------------------------------------------------

	// Reset failed attempts and update last login.
	if err := s.userRepo.ResetLoginAttempts(
		ctx,
		foundUser.ID,
	); err != nil {
		return nil, nil, err
	}

	// Create session.
	session, err := s.sessionRepo.Create(
		ctx,
		foundUser.ID,
		time.Duration(sessionTimeoutMinutes)*time.Minute,
	)
	if err != nil {
		return nil, nil, err
	}

	// Update returned user object.
	foundUser.FailedLoginAttempts = 0
	foundUser.LockedUntil = nil

	now := time.Now()
	foundUser.LastLoginAt = &now

	return foundUser, session, nil
}

// EnableMFA generates a TOTP secret and stores it as
// a pending MFA secret.
//
// MFA is NOT enabled at this point.
// The user must verify the TOTP code first.
func (s *Service) EnableMFA(
	ctx context.Context,
	userID string,
	username string,
) (*otp.Key, error) {

	key, err := GenerateTOTP(username)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to generate TOTP secret: %w",
			err,
		)
	}

	// Store secret as pending.
	// MFA remains disabled.
	if err := s.userRepo.SetPendingMFA(
		ctx,
		userID,
		key.Secret(),
	); err != nil {
		return nil, err
	}

	return key, nil
}

// VerifyMFA verifies the pending TOTP setup.
//
// If the code is correct, the pending secret becomes
// the active MFA secret and MFA is enabled.
func (s *Service) VerifyMFA(
	ctx context.Context,
	userID string,
	code string,
) error {

	code = strings.TrimSpace(code)

	if code == "" {
		return ErrMFARequired
	}

	foundUser, err := s.userRepo.FindByID(
		ctx,
		userID,
	)
	if err != nil {
		return err
	}

	// There must be a pending MFA setup.
	if foundUser.MFAPendingSecret == nil ||
		*foundUser.MFAPendingSecret == "" {

		return errors.New(
			"no pending 2FA setup found",
		)
	}

	// Validate code against pending secret.
	if !ValidateTOTP(
		code,
		*foundUser.MFAPendingSecret,
	) {
		return ErrInvalidTOTP
	}

	// Move pending secret to active secret
	// and enable MFA.
	if err := s.userRepo.ConfirmMFA(
		ctx,
		userID,
	); err != nil {
		return err
	}

	return nil
}

// DisableMFA disables MFA for the user.
func (s *Service) DisableMFA(
	ctx context.Context,
	userID string,
) error {

	return s.userRepo.DisableMFA(
		ctx,
		userID,
	)
}