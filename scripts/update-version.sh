#!/usr/bin/env bash
# Sets the release version: the VERSION file and every workspace crate's
# package version. Cargo.lock is refreshed by the caller (scripts/release.sh).
#
# Usage: scripts/update-version.sh <version>
# Example: scripts/update-version.sh 0.2.0
set -euo pipefail

version=${1:-}
if ! [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then
    echo "Usage: $0 <version>   (semver, e.g. 0.2.0 or 0.2.0-rc.1)" >&2
    exit 1
fi

cd "$(dirname "$0")/.."

echo "$version" > VERSION
# The workspace members: the first `version = ` line is the [package] one.
for toml in crates/*/Cargo.toml; do
    sed -i "0,/^version = \"[^\"]*\"/s//version = \"$version\"/" "$toml"
done

echo "Version set to $version:"
echo "  VERSION: $(cat VERSION)"
grep -H -m1 '^version = ' crates/*/Cargo.toml | sed 's/^/  /'
