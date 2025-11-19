# Multi-stage build for WebSec proxy
# Stage 1: Build environment
FROM rust:1.83-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig

# Set working directory
WORKDIR /usr/src/websec

# Copy dependency manifests
COPY Cargo.toml Cargo.lock ./

# Copy actual source code
COPY src ./src
COPY config ./config

# Build the actual application
RUN cargo build --release

# Stage 2: Runtime environment
FROM alpine:3.21

# Install runtime dependencies
RUN apk add --no-cache ca-certificates wget openssl libgcc

# Create non-root user
RUN addgroup -g 1000 websec && \
    adduser -D -u 1000 -G websec websec

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /usr/src/websec/target/release/websec /app/websec

# Copy configuration
COPY --from=builder /usr/src/websec/config /app/config

# Change ownership
RUN chown -R websec:websec /app

# Switch to non-root user
USER websec

# Expose proxy port and metrics port
EXPOSE 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/metrics || exit 1

# Run WebSec
CMD ["/app/websec", "run", "--config", "/app/config/websec.toml"]
