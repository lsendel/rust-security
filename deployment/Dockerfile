# Multi-stage Dockerfile for Auth Service with Enhanced Security Features
# Optimized for production with minimal attack surface

# Build stage
FROM rust:1.75-slim as builder

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy manifests and lock file first for better caching
COPY Cargo.toml Cargo.lock ./
COPY auth-service/Cargo.toml ./auth-service/
COPY common/Cargo.toml ./common/
COPY compliance-tools/Cargo.toml ./compliance-tools/
COPY policy-service/Cargo.toml ./policy-service/
COPY security-features/Cargo.toml ./security-features/
COPY soar-integration/Cargo.toml ./soar-integration/

# Create dummy source files to cache dependencies
RUN mkdir -p auth-service/src common/src compliance-tools/src \
    policy-service/src security-features/src soar-integration/src && \
    echo "fn main() {}" > auth-service/src/main.rs && \
    echo "// dummy" > auth-service/src/lib.rs && \
    echo "// dummy" > common/src/lib.rs && \
    echo "// dummy" > compliance-tools/src/lib.rs && \
    echo "fn main() {}" > policy-service/src/main.rs && \
    echo "// dummy" > policy-service/src/lib.rs && \
    echo "// dummy" > security-features/src/lib.rs && \
    echo "// dummy" > soar-integration/src/lib.rs

# Build dependencies only
RUN cargo build --release --bin auth-service
RUN rm -rf auth-service/src common/src compliance-tools/src \
    policy-service/src security-features/src soar-integration/src

# Copy actual source code
COPY auth-service/src ./auth-service/src
COPY common/src ./common/src
COPY compliance-tools/src ./compliance-tools/src
COPY policy-service/src ./policy-service/src
COPY security-features/src ./security-features/src
COPY soar-integration/src ./soar-integration/src

# Copy additional files
COPY auth-service/benches ./auth-service/benches
COPY auth-service/tests ./auth-service/tests
COPY examples ./examples

# Build the application with optimizations
ENV RUSTFLAGS="-C target-cpu=native -C link-arg=-s"
RUN cargo build --release --bin auth-service

# Runtime stage - use minimal base image
FROM debian:bookworm-slim

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r authservice \
    && useradd -r -g authservice -s /bin/false authservice

# Create necessary directories
RUN mkdir -p /app/config /app/logs /app/ssl \
    && chown -R authservice:authservice /app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/auth-service /app/auth-service

# Copy configuration files
COPY deployment/config/ /app/config/

# Set ownership and permissions
RUN chown authservice:authservice /app/auth-service \
    && chmod 755 /app/auth-service \
    && chmod -R 644 /app/config/ \
    && chmod -R 755 /app/logs/

# Switch to non-root user
USER authservice

# Set working directory
WORKDIR /app

# Set environment variables
ENV RUST_LOG=info
ENV RUST_BACKTRACE=1
ENV CONFIG_PATH=/app/config/production.toml

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose ports
EXPOSE 8080 9090

# Run the binary
ENTRYPOINT ["./auth-service"]