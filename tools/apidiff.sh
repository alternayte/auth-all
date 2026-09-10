#!/usr/bin/env bash
# Compare the exported API of every published package with the last release.
#
# NFR-09 asks for no incompatible change. The script writes a snapshot of the
# base tag in a temporary worktree, and compares the current tree with it.
set -euo pipefail

base="${1:-v0.3.0}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! git -C "$repo" rev-parse --verify --quiet "$base^{commit}" > /dev/null; then
    # A shallow clone carries no tag. The fetch adds the missing objects.
    git -C "$repo" fetch --quiet --tags --unshallow 2> /dev/null ||
        git -C "$repo" fetch --quiet --tags || true
fi
if ! git -C "$repo" rev-parse --verify --quiet "$base^{commit}" > /dev/null; then
    echo "apidiff: the base $base is not in this checkout." >&2
    echo "apidiff: fetch the tags, or name another base: ./tools/apidiff.sh <ref>" >&2
    exit 1
fi

work="$(mktemp -d)"
snapshots="$(mktemp -d)"
git -C "$repo" worktree add -q --detach "$work" "$base"
trap 'git -C "$repo" worktree remove --force "$work" >/dev/null 2>&1 || true' EXIT

packages="$(cd "$work" && go list ./... | grep -v /internal/ | grep -v /examples/ | grep -v /tools/ | grep -v /cmd/)"
status=0
for package in $packages; do
    file="$snapshots/$(echo "$package" | tr '/' '_').api"
    (cd "$work" && go tool -modfile="$repo/tools.go.mod" apidiff -w "$file" "$package")
    report="$(cd "$repo" && go tool -modfile="$repo/tools.go.mod" apidiff "$file" "$package")"
    if grep -q "Incompatible changes:" <<<"$report"; then
        echo "incompatible change in $package"
        echo "$report"
        status=1
    fi
done
if [ "$status" -eq 0 ]; then
    echo "apidiff: no incompatible change against $base"
fi
exit "$status"
