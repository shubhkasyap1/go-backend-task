````markdown
# Go Backend Task — Secure CLI Authentication System

A containerized Go authentication system with PostgreSQL persistence, bcrypt password hashing, session management, account lockout, and optional TOTP-based two-factor authentication (2FA).

The project provides both a REST API and an interactive command-line client.

---

## Features

- User registration
- Secure password hashing using bcrypt
- Username/password authentication
- TOTP-based 2FA compatible with authenticator applications
- Two-step login when 2FA is enabled
- Session creation and expiration
- Logout and session invalidation
- Account lockout after repeated failed login attempts
- Configurable session timeout
- PostgreSQL database
- Persistent database storage using Docker volumes
- Database migrations
- REST API using Gin
- Interactive CLI
- CLI command history
- CLI tab completion
- Docker and Docker Compose support
- Unit tests for password hashing and TOTP functionality

---

## Tech Stack

| Technology | Purpose |
|---|---|
| Go | Backend and CLI |
| Gin | REST API |
| PostgreSQL | Database |
| pgx | PostgreSQL driver |
| bcrypt | Password hashing |
| TOTP | Two-factor authentication |
| Docker | Containerization |
| Docker Compose | Application orchestration |

---

## Project Structure

go-backend-task/
│
├── cmd/
│   ├── cli/
│   │   └── main.go
│   └── server/
│       └── main.go
│
├── internal/
│   ├── auth/
│   │   ├── handler.go
│   │   ├── service.go
│   │   ├── session.go
│   │   └── service_test.go
│   │
│   ├── cli/
│   │   └── ...
│   │
│   ├── config/
│   │   └── config.go
│   │
│   ├── database/
│   │   ├── migrations/
│   │   └── ...
│   │
│   ├── middleware/
│   │   └── auth.go
│   │
│   └── user/
│       ├── model.go
│       └── repository.go
│
├── Dockerfile
├── docker-compose.yml
├── go.mod
├── go.sum
└── README.md
````

---

# Getting Started

## Prerequisites

You need:

* Docker
* Docker Compose
* Go 1.26+ (only required if running the CLI or server directly outside Docker)

Check your installations:

```bash
docker --version
docker compose version
go version
```

---

# Running with Docker

The recommended way to run the application is with Docker Compose.

## 1. Clone the repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd go-backend-task
```

## 2. Build the containers

```bash
docker compose build
```

For a completely fresh build:

```bash
docker compose build --no-cache
```

## 3. Start the application

```bash
docker compose up -d
```

Check the containers:

```bash
docker compose ps
```

Expected services:

```text
go-auth-app
go-auth-postgres
```

The API runs on:

```text
http://localhost:8080
```

PostgreSQL is exposed on:

```text
localhost:5433
```

---

# Health Check

Check whether the server is running:

```bash
curl http://localhost:8080/health
```

Expected response:

```json
{
  "status": "ok"
}
```

---

# Configuration

The application supports environment-based configuration.

| Variable                  |     Default | Description                    |
| ------------------------- | ----------: | ------------------------------ |
| `APP_PORT`                |      `8080` | API server port                |
| `DB_HOST`                 | `localhost` | PostgreSQL host                |
| `DB_PORT`                 |      `5432` | PostgreSQL port                |
| `DB_USER`                 |  `postgres` | Database user                  |
| `DB_PASSWORD`             |  `postgres` | Database password              |
| `DB_NAME`                 |    `authdb` | Database name                  |
| `SESSION_TIMEOUT_MINUTES` |        `30` | Session lifetime               |
| `MAX_LOGIN_ATTEMPTS`      |         `5` | Failed attempts before lockout |
| `LOCKOUT_MINUTES`         |        `15` | Account lockout duration       |

Inside Docker Compose, the application connects to PostgreSQL using the service name:

```text
DB_HOST=postgres
DB_PORT=5432
```

The host machine can access PostgreSQL through:

```text
localhost:5433
```

---

# REST API

Base URL:

```text
http://localhost:8080/api/v1/auth
```

---

## Register

### Request

```http
POST /api/v1/auth/register
```

Example:

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "SecurePass123!"
  }'
```

---

## Login

### Request

```http
POST /api/v1/auth/login
```

Example:

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "SecurePass123!"
  }'
```

If 2FA is disabled, successful authentication creates a session.

If 2FA is enabled, the response indicates that a TOTP verification is required.

---

# Two-Factor Authentication

The application uses TOTP-based two-factor authentication.

Authenticator applications such as Google Authenticator or compatible TOTP applications can be used.

## Enable 2FA

```http
POST /api/v1/auth/enable-2fa
```

Requires an authenticated session.

The response provides the information required to configure the authenticator application.

---

## Verify 2FA Setup

```http
POST /api/v1/auth/verify-2fa
```

Send the current 6-digit authenticator code.

Example:

```json
{
  "code": "123456"
}
```

After successful verification, 2FA becomes enabled for the account.

---

## Login with 2FA

When 2FA is enabled, authentication happens in two steps.

### Step 1 — Username and password

```http
POST /api/v1/auth/login
```

The server responds with an MFA-required status and the authenticated user's ID for the second step.

### Step 2 — TOTP verification

```http
POST /api/v1/auth/login/2fa
```

Example:

```json
{
  "user_id": "USER_ID",
  "code": "123456"
}
```

A valid TOTP code creates the authenticated session.

---

## Disable 2FA

```http
POST /api/v1/auth/disable-2fa
```

Requires an authenticated session.

---

# Session Management

After successful authentication, the server creates a session.

The session:

* Has a configurable expiration time
* Is associated with the authenticated user
* Is required for protected endpoints
* Can be invalidated using logout

Default session timeout:

```text
30 minutes
```

---

## Get Current User

```http
GET /api/v1/auth/me
```

Requires authentication.

The endpoint returns the current authenticated user's information.

---

## Logout

```http
POST /api/v1/auth/logout
```

Requires authentication.

The current session is invalidated.

---

# Account Lockout

The application protects against repeated failed login attempts.

Default configuration:

```text
Maximum failed attempts: 5
Lockout duration: 15 minutes
```

After the maximum number of failed attempts is reached, the account is temporarily locked.

During the lockout period, login attempts are rejected.

The values can be changed using:

```text
MAX_LOGIN_ATTEMPTS
LOCKOUT_MINUTES
```

---

# Interactive CLI

The project includes an interactive command-line client.

Start the CLI with:

```bash
go run ./cmd/cli
```

The API server and PostgreSQL database should already be running.

---

## Commands Before Login

Available commands:

```text
register
login
help
exit
```

### Register

```text
register
```

Creates a new account.

### Login

```text
login
```

Authenticates using username and password.

If 2FA is enabled, the CLI automatically asks for the TOTP code as the second authentication step.

### Help

```text
help
```

Displays available commands.

### Exit

```text
exit
```

Closes the CLI.

---

# Commands After Login

After successful authentication:

```text
whoami
enable-2fa
disable-2fa
logout
help
```

### whoami

```text
whoami
```

Displays information about the authenticated account, including:

* Username
* Registration date
* MFA status
* Session expiration
* Last login time, when available

### enable-2fa

```text
enable-2fa
```

Starts the TOTP setup process.

### disable-2fa

```text
disable-2fa
```

Disables TOTP authentication.

### logout

```text
logout
```

Terminates the current session.

### help

```text
help
```

Displays commands available after authentication.

---

# CLI Usability

The CLI supports:

* Interactive prompts
* Command history
* Arrow-key navigation through previous commands
* Tab completion
* Clear authentication error messages
* Clear success messages

---

# Security

The application implements several security measures.

## Password Hashing

Passwords are never stored in plaintext.

Passwords are hashed using bcrypt before being stored in PostgreSQL.

---

## Authentication

User authentication verifies the supplied password against the stored bcrypt hash.

Invalid credentials return an authentication error without exposing whether the username exists.

---

## Two-Factor Authentication

TOTP provides an additional authentication factor after password verification.

TOTP secrets are stored separately from passwords.

The login flow requires successful TOTP verification before creating an authenticated session.

---

## Account Lockout

Repeated failed login attempts are tracked.

After the configured threshold is reached, the account is temporarily locked.

---

## Sessions

Authenticated requests require a valid session.

Sessions have an expiration time and can be explicitly invalidated during logout.

---

# Database Persistence

PostgreSQL runs in its own Docker container.

The database uses a named Docker volume:

```text
postgres_data
```

This ensures database data survives normal container restarts and recreation.

To view Docker volumes:

```bash
docker volume ls
```

The project uses database migrations to create and update the required database schema.

---

# Running Tests

Run all Go tests:

```bash
go test ./...
```

Expected output should include:

```text
ok      internal/auth
```

The test suite currently covers important authentication functionality including:

* Password hashing
* Password verification
* TOTP generation
* TOTP validation
* Invalid TOTP rejection

---

# Useful Docker Commands

## Start

```bash
docker compose up -d
```

## Stop

```bash
docker compose down
```

## View application logs

```bash
docker compose logs app --tail=50
```

## Follow application logs

```bash
docker compose logs -f app
```

## View database logs

```bash
docker compose logs postgres --tail=50
```

## Rebuild

```bash
docker compose build --no-cache
```

## Restart

```bash
docker compose restart
```

## Check container status

```bash
docker compose ps
```

> Do not use `docker compose down -v` unless you intentionally want to delete the PostgreSQL volume and all persisted database data.

---

# API Endpoints Summary

| Method | Endpoint                   | Authentication |
| ------ | -------------------------- | -------------- |
| `GET`  | `/health`                  | Public         |
| `POST` | `/api/v1/auth/register`    | Public         |
| `POST` | `/api/v1/auth/login`       | Public         |
| `POST` | `/api/v1/auth/login/2fa`   | Public         |
| `GET`  | `/api/v1/auth/me`          | Required       |
| `POST` | `/api/v1/auth/logout`      | Required       |
| `POST` | `/api/v1/auth/enable-2fa`  | Required       |
| `POST` | `/api/v1/auth/disable-2fa` | Required       |
| `POST` | `/api/v1/auth/verify-2fa`  | Required       |

---

# Assignment Requirements Checklist

* [x] User registration
* [x] Username/password login
* [x] Secure password hashing
* [x] Optional TOTP 2FA
* [x] Google Authenticator-compatible TOTP
* [x] Session management
* [x] Configurable session timeout
* [x] Failed login tracking
* [x] Account lockout
* [x] PostgreSQL database
* [x] Persistent database storage
* [x] Database migrations
* [x] Dockerfile
* [x] Docker Compose
* [x] Interactive CLI
* [x] CLI command history
* [x] CLI tab completion
* [x] Clear success/error messages
* [x] Unit tests
* [x] README documentation

---

# Troubleshooting

## Application container keeps restarting

Check:

```bash
docker compose logs app --tail=100
```

Make sure the migration files are present and included in the Docker image.

---

## Database connection problems

Check:

```bash
docker compose ps
```

Both services should be running.

Inside Docker Compose, the application should use:

```text
DB_HOST=postgres
DB_PORT=5432
```

Do not use `localhost` for the PostgreSQL host from inside the application container.

---

## Port already in use

If port `8080` is already being used, change the host-side port mapping in `docker-compose.yml`.

For example:

```yaml
ports:
  - "8081:8080"
```

The application will still listen on port `8080` inside the container.

---

# Development

Run the server directly without Docker:

```bash
go run ./cmd/server
```

Run the CLI:

```bash
go run ./cmd/cli
```

Run tests:

```bash
go test ./...
```

---

# Author

**Shubham Kumar**

Go Backend Assignment — Osto

````
