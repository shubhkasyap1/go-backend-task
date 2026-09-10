package config

import (
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	AppPort               string
	DBHost                string
	DBPort                string
	DBUser                string
	DBPassword            string
	DBName                string
	SessionTimeoutMinutes int
	MaxLoginAttempts      int
	LockoutMinutes        int
}

func Load() Config {
	_ = godotenv.Load()

	return Config{
		AppPort:               getEnv("APP_PORT", "8080"),
		DBHost:                getEnv("DB_HOST", "localhost"),
		DBPort:                getEnv("DB_PORT", "5432"),
		DBUser:                getEnv("DB_USER", "postgres"),
		DBPassword:            getEnv("DB_PASSWORD", "postgres"),
		DBName:                getEnv("DB_NAME", "authdb"),
		SessionTimeoutMinutes: getEnvInt("SESSION_TIMEOUT_MINUTES", 30),
		MaxLoginAttempts:      getEnvInt("MAX_LOGIN_ATTEMPTS", 5),
		LockoutMinutes:        getEnvInt("LOCKOUT_MINUTES", 15),
	}
}

func getEnv(key, fallback string) string {
	value := os.Getenv(key)

	if value == "" {
		return fallback
	}

	return value
}

func getEnvInt(key string, fallback int) int {
	value := os.Getenv(key)

	if value == "" {
		return fallback
	}

	result, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}

	return result
}
