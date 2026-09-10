package database

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
)

func RunMigrations(ctx context.Context, db *pgxpool.Pool) error {
	_, err := db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(255) PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create migration table: %w", err)
	}

	migrationDir := "internal/database/migrations"

	files, err := os.ReadDir(migrationDir)
	if err != nil {
		return fmt.Errorf("failed to read migrations directory: %w", err)
	}

	var migrationFiles []string

	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".sql" {
			migrationFiles = append(migrationFiles, file.Name())
		}
	}

	sort.Strings(migrationFiles)

	for _, fileName := range migrationFiles {
		var exists bool

		err := db.QueryRow(
			ctx,
			`SELECT EXISTS (
				SELECT 1
				FROM schema_migrations
				WHERE version = $1
			)`,
			fileName,
		).Scan(&exists)

		if err != nil {
			return fmt.Errorf(
				"failed to check migration %s: %w",
				fileName,
				err,
			)
		}

		if exists {
			continue
		}

		path := filepath.Join(migrationDir, fileName)

		sqlBytes, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf(
				"failed to read migration %s: %w",
				fileName,
				err,
			)
		}

		tx, err := db.Begin(ctx)
		if err != nil {
			return fmt.Errorf(
				"failed to begin migration %s: %w",
				fileName,
				err,
			)
		}

		_, err = tx.Exec(ctx, string(sqlBytes))
		if err != nil {
			_ = tx.Rollback(ctx)

			return fmt.Errorf(
				"failed to execute migration %s: %w",
				fileName,
				err,
			)
		}

		_, err = tx.Exec(
			ctx,
			`INSERT INTO schema_migrations (version)
			 VALUES ($1)`,
			fileName,
		)
		if err != nil {
			_ = tx.Rollback(ctx)

			return fmt.Errorf(
				"failed to record migration %s: %w",
				fileName,
				err,
			)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf(
				"failed to commit migration %s: %w",
				fileName,
				err,
			)
		}

		fmt.Printf("Applied migration: %s\n", fileName)
	}

	return nil
}
