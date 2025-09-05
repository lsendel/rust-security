# Multi-stage Dockerfile for Auth-as-a-Service MVP
FROM rust:1.80-bookworm as builder

# Install required packages
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy workspace configuration
COPY Cargo.toml Cargo.lock ./
COPY auth-service/Cargo.toml ./auth-service/
COPY common/Cargo.toml ./common/
COPY mvp-tools/Cargo.toml ./mvp-tools/

# Create dummy source files to cache dependencies
RUN mkdir -p auth-service/src common/src mvp-tools/src && \
    echo "fn main() {}" > auth-service/src/main.rs && \
    echo "// dummy" > auth-service/src/lib.rs && \
    echo "// dummy" > common/src/lib.rs && \
    echo "// dummy" > mvp-tools/src/lib.rs

# Build dependencies (cached layer)
RUN cargo build --release --features security-essential && \
    rm auth-service/src/*.rs common/src/*.rs mvp-tools/src/*.rs

# Copy source code
COPY auth-service/src ./auth-service/src
COPY common/src ./common/src  
COPY mvp-tools/src ./mvp-tools/src

# Build the application
RUN cargo build --release --features security-essential

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN groupadd -r authuser && useradd -r -g authuser authuser

# Create app directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/target/release/auth-service /app/auth-service

# Copy configuration
COPY docker-entrypoint.sh /app/
RUN chmod +x /app/docker-entrypoint.sh

# Set ownership
RUN chown -R authuser:authuser /app
USER authuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose port
EXPOSE 8080

# Set environment defaults
ENV RUST_LOG=info
ENV BIND_ADDRESS=0.0.0.0:8080
ENV JWT_SECRET=change-me-in-production-minimum-32-characters-long
ENV ENABLE_METRICS=true
ENV ENABLE_API_KEYS=true
ENV RATE_LIMIT_ENABLED=true

# Start the application
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["./auth-service"]