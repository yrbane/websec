# Multi-stage build for WebSec proxy
# Stage 1: Build environment
FROM rust:1.83-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig

# Set working directory
WORKDIR /usr/src/websec

# Copy dependency manifests first to cache dependencies
COPY Cargo.toml Cargo.lock ./

# Create dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "fn lib() {}" > src/lib.rs

# Build dependencies only (this layer will be cached if Cargo.toml/lock don't change)
RUN cargo build --release

# Copy actual source code
COPY src ./src
COPY config ./config

# Touch main.rs to force rebuild of main crate
RUN touch src/main.rs

# Build the actual application
RUN cargo build --release

# Stage 2: Runtime environment
FROM alpine:3.21

# Install runtime dependencies
RUN apk add --no-cache ca-certificates openssl libgcc

# Create non-root user
RUN addgroup -g 1000 websec && \
    adduser -D -u 1000 -G websec websec

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /usr/src/websec/target/release/websec /app/websec

# Copy configuration
COPY --from=builder /usr/src/websec/config /app/config

# Ensure directory permissions
RUN mkdir -p /app/data && \
    chown -R websec:websec /app

# Switch to non-root user
USER websec

# Environment variables
ENV WEBSEC_CONFIG=/app/config/websec.toml

# Expose proxy port and metrics port
EXPOSE 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:9090/metrics || exit 1

# Run WebSec
CMD ["/app/websec", "run"]