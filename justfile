# Auth-All development commands.
#
# `just verify` is the canonical implementation-complete gate. It runs every
# deterministic v1 check and starts the databases it needs.

set shell := ["bash", "-euo", "pipefail", "-c"]

postgres_dsn := env_var_or_default("AUTHALL_POSTGRES_DSN", "postgres://authall:authall@127.0.0.1:55432/authall?sslmode=disable")
# Verification makes the PostgreSQL run mandatory. A missing database fails the
# check here, and skips outside of verification.
pg := "AUTHALL_REQUIRE_POSTGRES=1 AUTHALL_POSTGRES_DSN=\"" + postgres_dsn + "\""
pgbouncer_dsn := env_var_or_default("AUTHALL_PGBOUNCER_DSN", "postgres://authall:authall@127.0.0.1:56432/authall?sslmode=disable")
# The pooler run is mandatory in verification, and it skips outside of it.
bouncer := "AUTHALL_REQUIRE_PGBOUNCER=1 AUTHALL_PGBOUNCER_DSN=\"" + pgbouncer_dsn + "\""
compose := "docker compose -p authall-test -f docker-compose.test.yml"
checks := "artifacts/checks.tsv"

# Show the available commands.
default:
    @just --list

# Run every required v1 check. A failed check stops the run.
verify: _reset db-up fmt-check vet lint test-unit test-postgres test-pgbouncer test-sqlite test-http test-security test-concurrency test-race test-huma test-latency coverage apidiff generate-check ts-verify examples-build evidence
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
# The tools live in tools.go.mod, so the library go.mod never requires them. A
# tool directive there would raise the minimum Go version of every application
# that imports Auth-All.
lint:
    go tool -modfile=tools.go.mod staticcheck ./...
    @just _record "static analysis" "go tool -modfile=tools.go.mod staticcheck ./..."

# Start the test databases and wait until they are ready.
db-up:
    {{compose}} up -d --wait
    @just _record "test databases" "{{compose}} up -d --wait"

# Stop the test databases.
db-down:
    {{compose}} down -v

# Run the unit tests of the library packages.
test-unit:
    go test ./apierr/... ./email/... ./events/... ./hook/... ./openapi/... ./plugin/... ./ratelimit/... ./schema/... ./cmd/... ./oauth/... ./internal/crypto/... ./internal/totp/... ./internal/clientgen/...
    @just _record "unit tests" "go test ./apierr/... ./email/... ./events/... ./hook/... ./openapi/... ./plugin/... ./ratelimit/... ./schema/... ./cmd/... ./oauth/... ./internal/crypto/... ./internal/totp/... ./internal/clientgen/..."

# Run the storage contract suite against PostgreSQL.
test-postgres:
    {{pg}} go test ./store/postgres/... ./migrations/...
    @just _record "PostgreSQL storage contract" "go test ./store/postgres/... ./migrations/..."

# Run the storage contract suite through PgBouncer in transaction mode. The
# pooler gives one server connection for one transaction only, so a statement
# that needs a session fails here.
test-pgbouncer:
    {{bouncer}} go test -count 1 -run 'TestSCNPG003' ./store/postgres/...
    @just _record "PgBouncer transaction pool contract" "go test -run TestSCNPG003 ./store/postgres/..."

# Run the storage contract suite against SQLite.
test-sqlite:
    go test ./store/sqlite/... ./migrations/...
    @just _record "SQLite storage contract" "go test ./store/sqlite/... ./migrations/..."

# Run the HTTP integration and acceptance tests.
test-http:
    {{pg}} go test -run 'TestAUTH|TestPLUG|TestAPI|TestMIG|TestPostgres|TestMagicLink|TestOAuth|TestAccount|TestUnlink|TestUnknown|TestProvider|TestVerified|TestAutoLink|TestGeneration|TestDuplicate|TestConfig|TestPassword|TestStable|TestPlugin|TestTOTP|TestSignInWith|TestConfirmReturns|TestRecoveryCode|TestWrongRecoveryCode|TestRegenerate|TestRequireAuth|TestLoadSession|TestOIDC|TestTwoIssuers' .
    @just _record "HTTP integration tests" "just test-http"

# Run the security regression tests.
test-security:
    go test -run 'TestSEC|TestSession|TestSubject|TestCookie|TestUnsafe|TestWildcard|TestInvalid|TestGoogleIdentity|TestEnumeration|TestRedirectTargets|TestLinkState|TestSignInState|TestLinkCompletion|TestOAuthStateCookie' .
    @just _record "security regression tests" "just test-security"

# Run the concurrency tests.
test-concurrency:
    {{pg}} go test -race -run 'TestC00|TestAUTH013|TestConcurrentUnlink' -count 1 .
    {{pg}} go test -race -run 'TestStorageContract/Concurrent' -count 1 ./store/...
    @just _record "concurrency tests" "just test-concurrency"

# Run the complete suite under the race detector.
test-race:
    {{pg}} go test -race ./...
    @just _record "race detector" "go test -race ./..."

# Run the huma adapter module. It is a separate module, so it needs its own
# test run. HC-03 keeps huma out of the core module graph.
test-huma:
    cd humaauth && go vet ./... && go test -race ./...
    @just _record "huma adapter module" "cd humaauth && go test -race ./..."

# Measure the credential resolution latency. NFR-02 asks for a p99 below 2 ms.
# The step runs alone, because another test on the same database changes the
# measurement. AUTHALL_BENCH_FULL=1 uses the full volume of the requirement.
test-latency:
    {{pg}} AUTHALL_LATENCY=1 go test -count 1 -run TestNFR002 -v .
    @just _record "credential resolution latency" "just test-latency"

# Compare the exported API with the v1 release. NFR-09 asks for no
# incompatible change.
apidiff:
    ./tools/apidiff.sh
    @just _record "apidiff against v1" "./tools/apidiff.sh"

# Check the statement coverage of the packages that the v1.1 release adds.
# NFR-05 asks for 85 percent of statements in every new package.
coverage:
    #!/usr/bin/env bash
    set -euo pipefail
    export AUTHALL_REQUIRE_POSTGRES=1
    export AUTHALL_POSTGRES_DSN="{{postgres_dsn}}"
    profile="$(mktemp)"
    go test -count 1 -coverpkg=./plugins/...,./ratelimit/storelimit/...,./migrations/... \
        -coverprofile="$profile" ./... > /dev/null
    go run ./tools/coverage --profile "$profile" --minimum 85 \
        --package github.com/alternayte/auth-all/plugins/roles \
        --package github.com/alternayte/auth-all/plugins/apikeys \
        --package github.com/alternayte/auth-all/plugins/admin \
        --package github.com/alternayte/auth-all/ratelimit/storelimit \
        --package github.com/alternayte/auth-all/migrations
    just _record "new package coverage" "go run ./tools/coverage --minimum 85"

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

# Install the Node dependencies, typecheck, test, and build the TypeScript
# client. The build proves that the published package compiles.
ts-verify:
    npm ci
    # The client builds first. The React example imports the package by its
    # name, and the package entry points name ./dist, so a typecheck before the
    # build cannot resolve it. A local checkout hides this, because dist
    # survives from an earlier run.
    npm run build -w clients/typescript
    npm run typecheck
    npm test
    @just _record "TypeScript client typecheck and tests" "npm run typecheck && npm test"
    @just _record "TypeScript client package build" "npm run build -w clients/typescript"

# Build the official examples. The binaries go to a temporary directory, so
# the build never writes into the working tree.
examples-build:
    go build -o "$(mktemp -d)/" ./examples/...
    @just _record "example compilation" "go build -o \\$(mktemp -d)/ ./examples/..."

# Write the verification evidence.
evidence:
    {{pg}} go run ./tools/evidence --checks {{checks}} --out artifacts/v1.1-verification.md
    @echo "Evidence written to artifacts/v1.1-verification.md"

# Remove the recorded check results.
_reset:
    @mkdir -p artifacts
    @rm -f {{checks}}

# Record one passed check.
_record name command:
    @mkdir -p artifacts
    @printf '%s\t%s\tPASS\n' "{{name}}" "{{command}}" >> {{checks}}
