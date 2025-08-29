# Multi-stage build for optimal image size
FROM rust:1.75-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -m -u 1001 appuser

# Set working directory
WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY */Cargo.toml ./

# Create dummy source files to cache dependencies
RUN mkdir -p auth-core/src auth-service/src policy-service/src common/src api-contracts/src compliance-tools/src \
    && echo "fn main() {}" > auth-service/src/main.rs \
    && echo "fn main() {}" > policy-service/src/main.rs \
    && echo "fn main() {}" > compliance-tools/src/main.rs \
    && echo "" > auth-core/src/lib.rs \
    && echo "" > common/src/lib.rs \
    && echo "" > api-contracts/src/lib.rs \
    && echo "" > compliance-tools/src/lib.rs

# Build dependencies (cached layer)
RUN cargo build --release --workspace
RUN rm -rf auth-*/src policy-*/src common/src api-*/src compliance-*/src

# Copy source code
COPY . .

# Build application
RUN cargo build --release --workspace

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -m -u 1001 appuser

# Copy binaries
COPY --from=builder /app/target/release/auth-service /usr/local/bin/
COPY --from=builder /app/target/release/policy-service /usr/local/bin/
COPY --from=builder /app/target/release/security_metrics_collector /usr/local/bin/

# Copy configuration files
COPY --from=builder /app/config/ /app/config/

# Set ownership
RUN chown -R appuser:appuser /app /usr/local/bin/

# Switch to app user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose ports
EXPOSE 8080 8081

# Default command
CMD ["auth-service"]
