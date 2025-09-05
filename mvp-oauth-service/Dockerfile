# Multi-stage build for optimized production image
FROM rust:1.75 as builder

WORKDIR /usr/src/app

# Copy workspace files
COPY ../Cargo.toml ../Cargo.lock ./
COPY ../common ../common/
COPY ../mvp-tools ../mvp-tools/

# Copy OAuth service files
COPY . ./mvp-oauth-service/

# Build the application
WORKDIR /usr/src/app/mvp-oauth-service
RUN cargo build --release

# Runtime image
FROM debian:bookworm-slim

# Install CA certificates for HTTPS
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false mvpuser

WORKDIR /app

# Copy the binary
COPY --from=builder /usr/src/app/target/release/mvp-oauth /app/

# Set ownership
RUN chown mvpuser:mvpuser /app/mvp-oauth
RUN chmod +x /app/mvp-oauth

# Switch to non-root user
USER mvpuser

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# Run the application
CMD ["./mvp-oauth"]