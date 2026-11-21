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
# The API contract states the version of the control plane that serves it
# (customer_api::tests::the_contract_is_this_versions): info.version, the
# first "version" in the file.
openapi=crates/fenders-control-plane/static/api/openapi.json
sed -i "0,/\"version\": \"[^\"]*\"/s//\"version\": \"$version\"/" "$openapi"

echo "Version set to $version:"
echo "  VERSION: $(cat VERSION)"
grep -H -m1 '^version = ' crates/*/Cargo.toml | sed 's/^/  /'
grep -H -m1 '"version": ' "$openapi" | sed 's/^/  /'
