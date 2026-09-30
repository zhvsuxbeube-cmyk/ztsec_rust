# syntax=docker/dockerfile:1.7
FROM rust:1.92.0-bookworm
WORKDIR /src

# Copy dependency manifests and vendored Arti first so BuildKit can reuse the
# expensive dependency compilation layer when application sources change.
COPY Cargo.toml ./Cargo.toml
COPY protocol/Cargo.toml ./protocol/Cargo.toml
COPY server/Cargo.toml ./server/Cargo.toml
COPY vendor/arti/Cargo.toml ./vendor/arti/Cargo.toml
COPY vendor/arti/crates ./vendor/arti/crates

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo generate-lockfile

COPY protocol ./protocol
COPY server ./server
COPY src ./src
COPY plugin ./plugin
COPY telemetry_service.py ./telemetry_service.py
COPY python_service.py ./python_service.py

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --package ztsec_server --bin ztsec-server

RUN mkdir -p /out && cp target/release/ztsec-server /out/ztsec-server
FROM scratch AS artifacts
COPY --from=0 /out/ztsec-server /ztsec-server
