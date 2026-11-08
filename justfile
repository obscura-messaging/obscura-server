# List available recipes
default:
    @just --list

# Remove build artifacts
clean:
    cargo clean

# Type-check without building
check:
    cargo check

# Build debug binary
build:
    cargo build

# Format code
fmt:
    cargo fmt

# Check formatting without modifying files
fmt-check:
    cargo fmt -- --check

# Run clippy lints
clippy:
    cargo clippy --all-targets -- -D warnings

# Run tests
test:
    cargo test

# Run full CI suite locally
ci: fmt-check clippy coverage

# Start backing services for local development
services:
    docker compose up -d db minio valkey
    @echo "Waiting for services..."
    @docker compose exec db sh -c 'until pg_isready -U user -d signal_server; do sleep 1; done' > /dev/null 2>&1
    @until curl -sf http://localhost:9000/minio/health/live > /dev/null 2>&1; do sleep 1; done
    @docker compose exec -e AWS_ACCESS_KEY_ID=minioadmin -e AWS_SECRET_ACCESS_KEY=minioadmin minio sh -c "mkdir -p /data/test-bucket"
    @echo "Services ready."

# Stop backing services
services-down:
    docker compose down

# Generate LCOV coverage report
coverage:
    cargo llvm-cov \
        --lcov \
        --fail-under-lines 80 \
        --ignore-filename-regex '(tests/|build\.rs)' \
        --output-path lcov.info
    @echo ""
    @echo "Coverage report written to lcov.info"
    @awk '/^LH:/{h+=substr($0,4)} /^LF:/{t+=substr($0,4)} END{printf "Overall: %d/%d lines (%.1f%%)\n",h,t,(h/t)*100}' lcov.info

# Generate HTML coverage report
coverage-html:
    cargo llvm-cov \
        --html \
        --fail-under-lines 80 \
        --ignore-filename-regex '(tests/|build\.rs)' \
        --output-dir coverage/
    @echo ""
    @echo "HTML report written to coverage/"

# Remove coverage artifacts
clean-coverage:
    cargo llvm-cov clean
    rm -rf lcov.info coverage/

# Run mutation tests as isolated parallel shards (see scripts/mutants.sh)
mutants *args:
    scripts/mutants.sh {{args}}
