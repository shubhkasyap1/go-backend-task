package auth

import (
	"fmt"
	"context"
	"errors"
	"strings"
	"time"

	"github.com/pquerna/otp"

	"github.com/shubhkasyap1/go-backend-task/internal/user"
	
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrAccountLocked      = errors.New("account is temporarily locked")
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

func (s *Service) Login(
	ctx context.Context,
	username string,
	password string,
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

	if foundUser.LockedUntil != nil &&
		foundUser.LockedUntil.After(time.Now()) {
		return nil, nil, ErrAccountLocked
	}

	if !CheckPassword(password, foundUser.PasswordHash) {

		attempts, err := s.userRepo.RecordFailedLogin(
			ctx,
			foundUser.ID,
		)
		if err != nil {
			return nil, nil, err
		}

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

	if err := s.userRepo.ResetLoginAttempts(
		ctx,
		foundUser.ID,
	); err != nil {
		return nil, nil, err
	}

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

func (s *Service) EnableMFA(
	ctx context.Context,
	userID string,
	username string,
) (*otp.Key, error) {

	key, err := GenerateTOTP(username)
	if err != nil {
		return nil, err
	}

	if err := s.userRepo.EnableMFA(
		ctx,
		userID,
		key.Secret(),
	); err != nil {
		return nil, err
	}

	return key, nil
}

func (s *Service) DisableMFA(
	ctx context.Context,
	userID string,
) error {

	return s.userRepo.DisableMFA(
		ctx,
		userID,
	)
}

// func (s *Service) VerifyMFA(
// 	code string,
// 	secret string,
// ) bool {

// 	return ValidateTOTP(code, secret)
// }


func (s *Service) VerifyMFA(ctx context.Context, userID string, code string) error {
	foundUser, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return err
	}

	if !foundUser.MFAEnabled {
		return fmt.Errorf("2FA is not enabled")
	}

	if foundUser.MFASecret == nil || *foundUser.MFASecret == "" {
		return fmt.Errorf("2FA secret is missing")
	}

	if !ValidateTOTP(code, *foundUser.MFASecret) {
		return fmt.Errorf("invalid 2FA code")
	}

	return nil
}