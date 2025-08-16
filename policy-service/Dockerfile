# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

FROM chef AS planner
COPY ../../Cargo.toml ./Cargo.toml
COPY . ./policy-service
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY ../../Cargo.toml ./Cargo.toml
COPY . ./policy-service
RUN cargo build -p policy-service --release

FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/target/release/policy-service /usr/local/bin/policy-service
USER 65532:65532
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/policy-service"]

