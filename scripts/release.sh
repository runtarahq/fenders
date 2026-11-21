#!/usr/bin/env bash
# Release: bump the version, update VERSION, the crates' Cargo.toml files and
# Cargo.lock, commit, tag, and push. The tag push runs the release workflow,
# which builds the worker bundle and publishes it on the tag's GitHub release.
#
# Usage: scripts/release.sh <patch|minor|major>
# Example: scripts/release.sh patch   # 0.1.0 -> 0.1.1
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$script_dir/.."

bump=${1:-}
if [[ ! $bump =~ ^(patch|minor|major)$ ]]; then
    echo "Usage: $0 <patch|minor|major>" >&2
    echo "Example: $0 patch" >&2
    exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "Error: Working tree is not clean. Commit or stash your changes first." >&2
    exit 1
fi

# The current version is the latest v*.*.* tag; before the first one, VERSION.
latest_tag=$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -1)
if [[ -n $latest_tag ]]; then
    current=${latest_tag#v}
else
    current=$(tr -d '[:space:]' < VERSION)
    echo "No version tags yet; starting from VERSION ($current)."
fi
current=${current%%-*}
IFS=. read -r major minor patch <<< "$current"

echo "Current version: $current"
case $bump in
    major) major=$((major + 1)); minor=0; patch=0 ;;
    minor) minor=$((minor + 1)); patch=0 ;;
    patch) patch=$((patch + 1)) ;;
esac
version="$major.$minor.$patch"
tag="v$version"
echo "New version:     $version"
echo "Tag:             $tag"
echo

if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
    echo "Error: Tag $tag already exists." >&2
    exit 1
fi

"$script_dir/update-version.sh" "$version"

echo "Updating Cargo.lock workspace package versions..."
cargo update --workspace
echo "Verifying Cargo.lock is current..."
cargo metadata --locked --format-version 1 >/dev/null

git add -A
git commit -m "Release $version"
git tag "$tag"

echo
echo "Created commit and tag $tag."
echo
read -rp "Push commit and tag to origin? [y/N] " confirm
if [[ $confirm =~ ^[Yy]$ ]]; then
    git push origin HEAD "$tag"
    echo "Pushed. The release workflow will publish fenders-worker-$version.tar.gz on $tag."
else
    echo "Skipped push. Run manually:"
    echo "  git push origin HEAD $tag"
fi
