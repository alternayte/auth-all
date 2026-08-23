# Auth-All development commands.
#
# `just verify` is the canonical implementation-complete gate. It runs every
# deterministic v1 check and starts the databases it needs.

set shell := ["bash", "-euo", "pipefail", "-c"]

postgres_dsn := env_var_or_default("AUTHALL_POSTGRES_DSN", "postgres://authall:authall@127.0.0.1:55432/authall?sslmode=disable")
compose := "docker compose -p authall-test -f docker-compose.test.yml"
checks := "artifacts/checks.tsv"

# Show the available commands.
default:
    @just --list

# Run every required v1 check. A failed check stops the run.
verify: _reset db-up fmt-check vet lint test-unit test-postgres test-sqlite test-http test-security test-concurrency test-race generate-check ts-verify examples-build evidence
    @echo ""
    @echo "just verify: every required check passed."

# Format the Go sources.
fmt:
    gofmt -w .

# Check the formatting of the Go sources.
fmt-check:
    #!/usr/bin/env bash
    set -euo pipefail
    unformatted="$(gofmt -l .)"
    if [ -n "$unformatted" ]; then
        echo "These files are not formatted. Run: just fmt"
        echo "$unformatted"
        exit 1
    fi
    just _record "formatting" "gofmt -l ."

# Run the Go vet analysis.
vet:
    go vet ./...
    @just _record "go vet" "go vet ./..."

# Run the configured static analysis.
lint:
    go tool staticcheck ./...
    @just _record "static analysis" "go tool staticcheck ./..."

# Start the test databases and wait until they are ready.
db-up:
    {{compose}} up -d --wait
    @just _record "test databases" "{{compose}} up -d --wait"

# Stop the test databases.
db-down:
    {{compose}} down -v

# Run the unit tests of the library packages.
test-unit:
    go test ./apierr/... ./email/... ./events/... ./hook/... ./openapi/... ./plugin/... ./ratelimit/... ./schema/... ./internal/crypto/... ./internal/clientgen/...
    @just _record "unit tests" "go test ./apierr/... ./email/... ./events/... ./hook/... ./openapi/... ./plugin/... ./ratelimit/... ./schema/... ./internal/crypto/... ./internal/clientgen/..."

# Run the storage contract suite against PostgreSQL.
test-postgres:
    AUTHALL_POSTGRES_DSN="{{postgres_dsn}}" go test ./store/postgres/...
    @just _record "PostgreSQL storage contract" "go test ./store/postgres/..."

# Run the storage contract suite against SQLite.
test-sqlite:
    go test ./store/sqlite/...
    @just _record "SQLite storage contract" "go test ./store/sqlite/..."

# Run the HTTP integration and acceptance tests.
test-http:
    AUTHALL_POSTGRES_DSN="{{postgres_dsn}}" go test -run 'TestAUTH|TestPLUG|TestAPI|TestMIG|TestPostgres|TestMagicLink|TestOAuth|TestAccount|TestUnlink|TestUnknown|TestProvider|TestVerified|TestAutoLink|TestGeneration|TestDuplicate|TestConfig|TestPassword|TestStable|TestPlugin' .
    @just _record "HTTP integration tests" "just test-http"

# Run the security regression tests.
test-security:
    go test -run 'TestSEC|TestSession|TestCookie|TestUnsafe|TestWildcard|TestInvalid|TestGoogleIdentity|TestEnumeration|TestRedirectTargets|TestLinkState|TestSignInState|TestLinkCompletion|TestOAuthStateCookie' .
    @just _record "security regression tests" "just test-security"

# Run the concurrency tests.
test-concurrency:
    AUTHALL_POSTGRES_DSN="{{postgres_dsn}}" go test -race -run 'TestC00|TestAUTH013|TestConcurrentUnlink' -count 1 .
    AUTHALL_POSTGRES_DSN="{{postgres_dsn}}" go test -race -run 'TestStorageContract/Concurrent' -count 1 ./store/...
    @just _record "concurrency tests" "just test-concurrency"

# Run the complete suite under the race detector.
test-race:
    AUTHALL_POSTGRES_DSN="{{postgres_dsn}}" go test -race ./...
    @just _record "race detector" "go test -race ./..."

# Regenerate the OpenAPI contract and the TypeScript client.
generate:
    go run ./cmd/auth-all openapi --out api/openapi.json
    go run ./cmd/auth-all client --out clients/typescript/src/generated.ts

# Check that the generated artifacts match the sources.
generate-check: generate
    #!/usr/bin/env bash
    set -euo pipefail
    changed="$(git status --porcelain -- api/openapi.json clients/typescript/src/generated.ts)"
    if [ -n "$changed" ]; then
        echo "The generated artifacts are stale. Run: just generate"
        echo "$changed"
        git --no-pager diff -- api/openapi.json clients/typescript/src/generated.ts
        exit 1
    fi
    just _record "generated artifact freshness" "just generate && git status --porcelain"
    just _record "OpenAPI freshness" "go run ./cmd/auth-all openapi --out api/openapi.json"
    just _record "TypeScript client freshness" "go run ./cmd/auth-all client --out clients/typescript/src/generated.ts"

# Install the Node dependencies, typecheck, and test the TypeScript client.
ts-verify:
    npm ci
    npm run typecheck
    npm test
    @just _record "TypeScript client typecheck and tests" "npm run typecheck && npm test"

# Build the official examples. The binaries go to a temporary directory, so
# the build never writes into the working tree.
examples-build:
    go build -o "$(mktemp -d)/" ./examples/...
    @just _record "example compilation" "go build -o \\$(mktemp -d)/ ./examples/..."

# Write the v1 verification evidence.
evidence:
    AUTHALL_POSTGRES_DSN="{{postgres_dsn}}" go run ./tools/evidence --checks {{checks}} --out artifacts/v1-verification.md
    @echo "Evidence written to artifacts/v1-verification.md"

# Remove the recorded check results.
_reset:
    @mkdir -p artifacts
    @rm -f {{checks}}

# Record one passed check.
_record name command:
    @mkdir -p artifacts
    @printf '%s\t%s\tPASS\n' "{{name}}" "{{command}}" >> {{checks}}
