package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp"

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
//
// Flow:
//
//	Username + Password
//	       ↓
//	Password valid?
//	       ↓
//	MFA enabled?
//	  ↓           ↓
//	 NO          YES
//	  ↓           ↓
//	Session    Validate TOTP
//	              ↓
//	           Session
func (s *Service) Login(
	ctx context.Context,
	username string,
	password string,
	totpCode string,
	maxAttempts int,
	lockoutMinutes int,
	sessionTimeoutMinutes int,
) (*user.User, *Session, error) {

	username = strings.TrimSpace(username)

	foundUser, err := s.userRepo.FindByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, user.ErrUserNotFound) {
			return nil, nil, ErrInvalidCredentials
		}

		return nil, nil, err
	}

	// Check whether the account is currently locked.
	if foundUser.LockedUntil != nil &&
		foundUser.LockedUntil.After(time.Now()) {
		return nil, nil, ErrAccountLocked
	}

	// Verify password.
	if !CheckPassword(password, foundUser.PasswordHash) {

		attempts, err := s.userRepo.RecordFailedLogin(
			ctx,
			foundUser.ID,
		)
		if err != nil {
			return nil, nil, err
		}

		// Lock account after maximum failed attempts.
		if attempts >= maxAttempts {
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

	// If MFA is enabled, TOTP is mandatory.
	if foundUser.MFAEnabled {

		if foundUser.MFASecret == nil ||
			*foundUser.MFASecret == "" {
			return nil, nil, errors.New(
				"2FA is enabled but secret is missing",
			)
		}

		if strings.TrimSpace(totpCode) == "" {
			return nil, nil, ErrMFARequired
		}

		if !ValidateTOTP(
			totpCode,
			*foundUser.MFASecret,
		) {
			return nil, nil, ErrInvalidTOTP
		}
	}

	// Successful authentication.
	// Reset failed attempts and update last login time.
	if err := s.userRepo.ResetLoginAttempts(
		ctx,
		foundUser.ID,
	); err != nil {
		return nil, nil, err
	}

	// Create authenticated session.
	session, err := s.sessionRepo.Create(
		ctx,
		foundUser.ID,
		time.Duration(sessionTimeoutMinutes)*time.Minute,
	)
	if err != nil {
		return nil, nil, err
	}

	foundUser.LastLoginAt = &session.CreatedAt

	return foundUser, session, nil
}

// EnableMFA generates a TOTP secret and stores it as a
// pending MFA secret.
//
// MFA is NOT enabled at this point.
//
// The user must first verify a TOTP code using /verify-2fa.
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

	// Store the secret as pending.
	// Do NOT enable MFA yet.
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
		return errors.New("no pending 2FA setup found")
	}

	// Validate the code against the pending secret.
	if !ValidateTOTP(
		code,
		*foundUser.MFAPendingSecret,
	) {
		return ErrInvalidTOTP
	}

	// Move pending secret to active MFA secret
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
