# Identity Service

The identity service is a Go 1.25 application powered by Fiber v2, PostgreSQL, Zap logging, and Viper-based configuration. It exposes user registration, login, JWT issuance, and TOTP-backed two-factor authentication flows. This document summarizes the service layout, runtime expectations, and operational commands.

## Project Structure

- `app/identity` – HTTP handlers that implement business logic (register, login, 2FA enable/verify/disable, recovery-code management).
- `infra/postgres` – Database migrations and the `PgRepository` implementation backed by `database/sql`.
- `pkg/` – Shared utilities such as configuration loading, HTTP error helpers, JWT helpers, and the custom TOTP implementation.
- `internal/middleware/bearer_auth.go` – Validates Bearer tokens and injects the authenticated user into the request context.
- `docker-compose.yaml` & `Dockerfile` – Multi-stage build plus compose targets for production and the `dev` profile.

## Stack & Responsibilities

- Exposes REST endpoints through Fiber using the `handle` helper in `main.go` for consistent validation and error handling.
- Loads configuration from `config/config.yaml` and environment variables (managed through `pkg/config`).
- Persists users in PostgreSQL (`identity-postgres`) with the schema defined in `infra/postgres/migrations/001_create_users.sql`. Passwords are SHA-256 hashed.
- Issues and validates JWT access tokens via `pkg/jwt`; the middleware requires a Bearer header for protected routes.
- Implements 2FA with `pkg/totp`: enables/disables shared secrets, verifies user-provided codes, and stores recovery codes as JSON.
- Uses Zap for structured logging and centralized error responses via `pkg/httperror`.

## HTTP API (summary)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/register` | Public | Create a user (email, hashed password, name). Returns the new user ID. |
| `POST` | `/login` | Public | Authenticate. Returns `{ "token": "<jwt>" }` or `202 Accepted` with a temporary `jwt` and `expires_at` when 2FA is enabled. |
| `POST` | `/2fa/challenge` | Public | Exchange the temporary login JWT + OTP for the final access token. |
| `GET`  | `/me` | Bearer | Fetch profile info and 2FA status for the authenticated subject. |
| `POST` | `/2fa/enable` | Bearer | Generate (or return existing) TOTP secret and respond with an `otpauth://` URL for authenticator apps. |
| `POST` | `/2fa/verify` | Bearer | Validate an OTP, mark the user as verified, and return freshly generated recovery codes. |
| `POST` | `/2fa/disable` | Bearer | Reset 2FA flags, secret, and verification state (returns 204). |
| `GET`  | `/2fa/recovery-codes` | Bearer | Retrieve stored recovery codes (JSON array). |

## Two-Factor Flow

1. Call `POST /2fa/enable` and scan the returned `totp_url` with an authenticator app.
2. Confirm via `POST /2fa/verify` using the OTP from the authenticator; the API responds with recovery codes and persists both the verification flag and the codes.
3. After verification, `POST /login` responds with `202 Accepted` plus a temporary JWT (one-hour TTL). Call `POST /2fa/challenge` with `{ "jwt": "<temp>", "code": "123456" }` to obtain the final access token.
4. Recovery codes can be fetched via `GET /2fa/recovery-codes` and should be stored securely. `POST /2fa/disable` reverts to password-only logins.

## Configuration & Environment Variables

Configuration lives in `config/config.yaml`, but every value can be overridden via environment variables (Viper automatically upper-cases the keys).

| Config Key | Env Var | Description |
|------------|---------|-------------|
| `port` | `PORT` | HTTP listener port (default `8080`). |
| `postgres_username` | `POSTGRES_USERNAME` | Database user for the identity schema. |
| `postgres_password` | `POSTGRES_PASSWORD` | Database password. |
| `postgres_database` | `POSTGRES_DATABASE` | Database name (`auction`). |
| `postgres_sslmode` | `POSTGRES_SSLMODE` | PostgreSQL SSL mode (`disable`, `require`, etc.). |
| `postgres_host` | `POSTGRES_HOST` | Hostname of the per-service database container (`identity-postgres`). |
| `postgres_port` | `POSTGRES_PORT` | Database port (5432). |
| `jwt_secret` | `JWT_SECRET` | Symmetric secret used to sign and verify JWTs. Keep it safe. |

## Running the Service Locally

### Build and Run the Container Directly

```bash
docker build -t auction-identity ./identity
docker run --rm -p 8080:8080 \
  -e PORT=8080 \
  -e POSTGRES_HOST=postgres \
  -e POSTGRES_PORT=5432 \
  -e POSTGRES_USERNAME=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DATABASE=auction \
  -e POSTGRES_SSLMODE=disable \
  auction-identity
```

The image ships with `/config/config.yaml`; environment variables override the defaults at runtime.

### Run with Docker Compose

1. Boot the shared infrastructure (RabbitMQ + network):
   ```bash
   docker compose -f infra/docker/docker-compose.yaml up -d
   ```
2. Start the identity service and its dedicated PostgreSQL instance:
   ```bash
   docker compose -f identity/docker-compose.yaml up --build identity identity-postgres
   ```
   - The API listens on `localhost:8080`.
   - `identity-postgres` exposes `5432`, mounts `infra/postgres/migrations` for automatic schema creation, and participates in the private `identity-internal` network.
   - Both services attach to the external `rabbitmq-shared` network named `auction-rabbitmq-network`.

### Live Reload for Development

Use the `dev` profile, which leverages the `air` hot-reload runner and mounts the local source tree:

```bash
docker compose -f identity/docker-compose.yaml --profile dev up identity-dev identity-postgres
```

Avoid running the production container at the same time to prevent port collisions.

## Database & Migrations

- Each microservice owns its data store; never share databases between services.
- For identity, migrations live under `infra/postgres/migrations` and are mounted as `/docker-entrypoint-initdb.d` within the PostgreSQL container to bootstrap the schema (creates `users` table, `uuid-ossp` extension, indexes).
- If the `users` table is missing because the Docker volume existed beforehand, run:

  ```bash
  docker compose -f identity/docker-compose.yaml exec identity-postgres \
    psql -U postgres -d auction -f /docker-entrypoint-initdb.d/001_create_users.sql
  ```

  or drop the volume with `docker compose -f identity/docker-compose.yaml down -v` and restart the stack.

- Recovery codes are stored as JSON strings in the `two_factor_recovery_codes` column; helpers take care of marshaling/unmarshaling.
