# Multi-stage build for policy-service
FROM rust:1.83-bookworm AS builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files from root context
COPY Cargo.toml Cargo.lock ./
COPY auth-core/ ./auth-core/
COPY auth-service/ ./auth-service/
COPY policy-service/ ./policy-service/

# Build the policy-service binary
RUN cargo build --release --bin policy-service

# Runtime stage
FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/target/release/policy-service /usr/local/bin/policy-service
USER 65532:65532
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/policy-service"]

