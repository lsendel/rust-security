# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

FROM chef AS planner
COPY ../../Cargo.toml ./Cargo.toml
COPY . ./auth-service
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY ../../Cargo.toml ./Cargo.toml
COPY . ./auth-service
RUN cargo build -p auth-service --release

FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/target/release/auth-service /usr/local/bin/auth-service
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/auth-service"]

