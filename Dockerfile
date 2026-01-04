# Build stage
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /ocsp-responder .

# Final stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN adduser -D -g '' ocsp
USER ocsp

WORKDIR /app

# Copy binary from builder
COPY --from=builder /ocsp-responder /app/ocsp-responder

EXPOSE 8080

ENTRYPOINT ["/app/ocsp-responder"]
