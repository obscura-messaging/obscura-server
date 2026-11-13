# Stage 1: Builder
FROM rust:1.100-slim AS builder
WORKDIR /app

# Install build dependencies (protoc for the protobuf build script)
RUN apt-get update && apt-get install -y protobuf-compiler

# Copy manifests and build requirements
COPY ./Cargo.toml ./Cargo.lock* ./
COPY ./build.rs ./build.rs
COPY ./proto ./proto

# Build dependencies with empty main()
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release

# Copy in source and migrations
COPY ./src src
COPY ./migrations migrations
COPY ./openapi.yaml .

# Touch file to set modified time, then build
RUN touch src/main.rs
RUN cargo build --release

# Stage 2: Runtime
FROM debian:13.7-slim
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Create a non-root user with a specific UID/GID
RUN groupadd -g 10001 appuser && useradd -u 10001 -g 10001 -r appuser

# Copy binary to release image
COPY --from=builder --chown=appuser:appuser /app/target/release/obscura-server .

EXPOSE 3000 9090

# Switch to non-root user
USER appuser

# Run the application
CMD ["./obscura-server"]