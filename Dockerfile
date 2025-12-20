FROM golang:1.25.4 AS dev

WORKDIR /app

RUN go install github.com/air-verse/air@latest

COPY go.mod go.sum ./
RUN go mod download

COPY . .

CMD ["air", "-c", ".air.toml"]

FROM golang:1.25.4 AS builder

WORKDIR /src

# Download dependencies first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source
COPY . .

FROM builder AS builder-api
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /identity-api ./main.go

# API Service Runner
FROM gcr.io/distroless/base-debian12:nonroot AS api

WORKDIR /app

COPY --from=builder-api /identity-api /usr/local/bin/identity-api

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/identity-api"]
