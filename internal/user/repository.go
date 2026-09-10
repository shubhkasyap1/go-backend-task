package user

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrUserNotFound = errors.New("user not found")
var ErrUsernameExists = errors.New("username already exists")

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{
		db: db,
	}
}

func (r *Repository) Create(
	ctx context.Context,
	username string,
	passwordHash string,
) (*User, error) {

	user := &User{}

	query := `
		INSERT INTO users (
			username,
			password_hash
		)
		VALUES ($1, $2)
		RETURNING
			id,
			username,
			password_hash,
			mfa_enabled,
			mfa_secret,
			failed_login_attempts,
			locked_until,
			last_login_at,
			created_at,
			updated_at
	`

	err := r.db.QueryRow(
		ctx,
		query,
		username,
		passwordHash,
	).Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash,
		&user.MFAEnabled,
		&user.MFASecret,
		&user.FailedLoginAttempts,
		&user.LockedUntil,
		&user.LastLoginAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if isDuplicateKeyError(err) {
			return nil, ErrUsernameExists
		}

		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

func (r *Repository) FindByUsername(
	ctx context.Context,
	username string,
) (*User, error) {

	user := &User{}

	query := `
		SELECT
			id,
			username,
			password_hash,
			mfa_enabled,
			mfa_secret,
			failed_login_attempts,
			locked_until,
			last_login_at,
			created_at,
			updated_at
		FROM users
		WHERE username = $1
	`

	err := r.db.QueryRow(
		ctx,
		query,
		username,
	).Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash,
		&user.MFAEnabled,
		&user.MFASecret,
		&user.FailedLoginAttempts,
		&user.LockedUntil,
		&user.LastLoginAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	return user, nil
}

func isDuplicateKeyError(err error) bool {
	return err != nil &&
		(len(err.Error()) > 0 &&
			contains(err.Error(), "duplicate key"))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}()
}

func (r *Repository) RecordFailedLogin(
	ctx context.Context,
	userID string,
) (int, error) {
	var attempts int

	query := `
		UPDATE users
		SET
			failed_login_attempts = failed_login_attempts + 1,
			updated_at = NOW()
		WHERE id = $1
		RETURNING failed_login_attempts
	`

	err := r.db.QueryRow(ctx, query, userID).Scan(&attempts)
	if err != nil {
		return 0, fmt.Errorf("failed to record login attempt: %w", err)
	}

	return attempts, nil
}

func (r *Repository) LockAccount(
	ctx context.Context,
	userID string,
	lockUntil time.Time,
) error {
	query := `
		UPDATE users
		SET
			locked_until = $1,
			updated_at = NOW()
		WHERE id = $2
	`

	_, err := r.db.Exec(ctx, query, lockUntil, userID)
	if err != nil {
		return fmt.Errorf("failed to lock account: %w", err)
	}

	return nil
}

func (r *Repository) ResetLoginAttempts(
	ctx context.Context,
	userID string,
) error {
	query := `
		UPDATE users
		SET
			failed_login_attempts = 0,
			locked_until = NULL,
			last_login_at = NOW(),
			updated_at = NOW()
		WHERE id = $1
	`

	_, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to reset login attempts: %w", err)
	}

	return nil
}

func (r *Repository) FindByID(
	ctx context.Context,
	id string,
) (*User, error) {

	user := &User{}

	query := `
		SELECT
			id,
			username,
			password_hash,
			mfa_enabled,
			mfa_secret,
			failed_login_attempts,
			locked_until,
			last_login_at,
			created_at,
			updated_at
		FROM users
		WHERE id = $1
	`

	err := r.db.QueryRow(
		ctx,
		query,
		id,
	).Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash,
		&user.MFAEnabled,
		&user.MFASecret,
		&user.FailedLoginAttempts,
		&user.LockedUntil,
		&user.LastLoginAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	return user, nil
}
