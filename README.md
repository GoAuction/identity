# Identity Service

User authentication service with JWT token issuance and TOTP-based two-factor authentication.

## Features

- User registration and login
- JWT access tokens
- TOTP-based 2FA with recovery codes
- Bearer token middleware

## Quick Start

```bash
# Start shared infrastructure first
docker compose -f infra/docker/docker-compose.yaml up -d

# Development mode (hot reload)
docker compose --profile dev up identity-dev identity-postgres

# Production mode
docker compose up identity identity-postgres
```

### Local Development

```bash
POSTGRES_HOST=localhost \
POSTGRES_PORT=5432 \
POSTGRES_DATABASE=auction \
POSTGRES_USERNAME=postgres \
POSTGRES_PASSWORD=postgres \
JWT_SECRET=your-secret-key \
PORT=8080 \
go run main.go
```

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/register` | Public | Create user account |
| POST | `/login` | Public | Authenticate, get JWT |
| POST | `/2fa/challenge` | Public | Exchange temp JWT + OTP for access token |
| GET | `/me` | Bearer | Get user profile |
| POST | `/2fa/enable` | Bearer | Generate TOTP secret |
| POST | `/2fa/verify` | Bearer | Verify OTP, get recovery codes |
| POST | `/2fa/disable` | Bearer | Disable 2FA |
| GET | `/2fa/recovery-codes` | Bearer | Retrieve recovery codes |

## Two-Factor Authentication

### Enable 2FA

1. `POST /2fa/enable` → Returns `otpauth://` URL
2. Scan QR code with authenticator app
3. `POST /2fa/verify` with OTP → Returns recovery codes

### Login with 2FA

1. `POST /login` → Returns `202 Accepted` + temporary JWT (1h TTL)
2. `POST /2fa/challenge` with `{ "jwt": "<temp>", "code": "123456" }` → Returns access token

### Disable 2FA

`POST /2fa/disable` → Returns 204, reverts to password-only login

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP listener port |
| `POSTGRES_HOST` | `identity-postgres` | Database host |
| `POSTGRES_PORT` | `5432` | Database port |
| `POSTGRES_DATABASE` | `auction` | Database name |
| `POSTGRES_USERNAME` | `postgres` | Database user |
| `POSTGRES_PASSWORD` | `postgres` | Database password |
| `POSTGRES_SSLMODE` | `disable` | SSL mode |
| `JWT_SECRET` | - | JWT signing secret (required) |

## Database

Schema: `infra/postgres/migrations/001_create_users.sql`

- `users` table with password hash, 2FA secret, recovery codes
- Passwords are SHA-256 hashed
- Recovery codes stored as JSON

### Reset Database

```bash
docker compose down -v
docker compose up
```

## Project Structure

```
identity/
├── main.go                 # Entry point + routes
├── app/identity/           # HTTP handlers
├── domain/                 # User entity
├── internal/middleware/    # Bearer auth
├── infra/postgres/         # Repository + migrations
└── pkg/
    ├── config/             # Viper config
    ├── httperror/          # Error handling
    ├── jwt/                # Token utilities
    └── totp/               # 2FA implementation
```
