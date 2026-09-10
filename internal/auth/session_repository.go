package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrSessionNotFound = errors.New("session not found")

type SessionRepository struct {
	db *pgxpool.Pool
}

func NewSessionRepository(db *pgxpool.Pool) *SessionRepository {
	return &SessionRepository{
		db: db,
	}
}

func (r *SessionRepository) Create(
	ctx context.Context,
	userID string,
	duration time.Duration,
) (*Session, error) {

	session := &Session{}

	query := `
		INSERT INTO sessions (
			user_id,
			expires_at
		)
		VALUES ($1, $2)
		RETURNING
			id,
			user_id,
			expires_at,
			created_at
	`

	expiresAt := time.Now().Add(duration)

	err := r.db.QueryRow(
		ctx,
		query,
		userID,
		expiresAt,
	).Scan(
		&session.ID,
		&session.UserID,
		&session.ExpiresAt,
		&session.CreatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return session, nil
}

func (r *SessionRepository) FindValid(
	ctx context.Context,
	sessionID string,
) (*Session, error) {

	session := &Session{}

	query := `
		SELECT
			id,
			user_id,
			expires_at,
			created_at
		FROM sessions
		WHERE id = $1
		  AND expires_at > NOW()
	`

	err := r.db.QueryRow(
		ctx,
		query,
		sessionID,
	).Scan(
		&session.ID,
		&session.UserID,
		&session.ExpiresAt,
		&session.CreatedAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSessionNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("failed to find session: %w", err)
	}

	return session, nil
}

func (r *SessionRepository) Delete(
	ctx context.Context,
	sessionID string,
) error {

	_, err := r.db.Exec(
		ctx,
		`DELETE FROM sessions WHERE id = $1`,
		sessionID,
	)

	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	return nil
}
