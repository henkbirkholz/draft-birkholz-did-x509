#!/bin/bash
# Re-import test-vectors.json from upstream microsoft/did-x509, pinned to a
# commit recorded in tests/samples/UPSTREAM_COMMIT (the single source of
# truth for the pin, also used to install the reference implementation and
# its requirements.txt for tests/test_rego_policy.py).
#
# Usage:
#   scripts/update-test-vectors.sh [ref]
#
# With no argument, re-fetches at the currently pinned commit. With an
# argument, that argument is resolved to a full 40-character commit SHA
# (accepted as-is if it already is one, otherwise resolved as a branch or
# tag via `git ls-remote`, with an annotated tag resolved to the commit it
# points to) before anything is updated, so the pin can never be a moving
# ref such as "main".
set -euo pipefail

REPO_URL="https://github.com/microsoft/did-x509"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMMIT_FILE="$ROOT/tests/samples/UPSTREAM_COMMIT"

resolve_commit() {
  local ref="$1"
  if [[ "$ref" =~ ^[0-9a-f]{40}$ ]]; then
    printf '%s\n' "$ref"
    return
  fi
  # Ask for the branch and the tag explicitly. For an annotated tag, only the
  # peeled "^{}" entry names the commit; the tag entry names the tag object.
  local refs head tag peeled
  if ! refs="$(git ls-remote "$REPO_URL" "refs/heads/$ref" "refs/tags/$ref" "refs/tags/$ref^{}")"; then
    echo "error: could not list refs on $REPO_URL" >&2
    exit 1
  fi
  head="$(awk -v r="refs/heads/$ref" '$2 == r { print $1 }' <<<"$refs")"
  tag="$(awk -v r="refs/tags/$ref" '$2 == r { print $1 }' <<<"$refs")"
  peeled="$(awk -v r="refs/tags/$ref^{}" '$2 == r { print $1 }' <<<"$refs")"
  if [ -n "$head" ] && [ -n "$tag" ]; then
    echo "error: '$ref' is both a branch and a tag on $REPO_URL; pass a commit SHA" >&2
    exit 1
  fi
  if [ -n "$peeled" ]; then
    printf '%s\n' "$peeled"
  elif [ -n "$tag" ]; then
    printf '%s\n' "$tag"
  elif [ -n "$head" ]; then
    printf '%s\n' "$head"
  else
    echo "error: '$ref' is not a branch or tag on $REPO_URL" >&2
    exit 1
  fi
}

if [ "$#" -ge 1 ]; then
  COMMIT="$(resolve_commit "$1")"
else
  COMMIT="$(cat "$COMMIT_FILE")"
fi

if ! [[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
  echo "error: '$COMMIT' is not a full 40-character commit SHA" >&2
  exit 1
fi

TMP_VECTORS="$(mktemp)"
trap 'rm -f "$TMP_VECTORS"' EXIT

URL="https://raw.githubusercontent.com/microsoft/did-x509/$COMMIT/test-vectors.json"
curl -fsSL "$URL" -o "$TMP_VECTORS"

# Only update the checked-in files once the download has succeeded, so a
# failed download never leaves the pin moved without matching vectors.
mv "$TMP_VECTORS" "$ROOT/tests/samples/test-vectors.json"
echo "$COMMIT" > "$COMMIT_FILE"

echo "Imported test-vectors.json from microsoft/did-x509@$COMMIT"
