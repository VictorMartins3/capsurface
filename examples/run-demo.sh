#!/usr/bin/env bash
# Demonstrates capsurface catching a worm-like capability escalation between
# two versions of the same (fictional) npm package.
set -euo pipefail
cd "$(dirname "$0")/.."

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "== Step 1: scan the 'trusted' baseline version (2.3.0) =="
node bin/capsurface.js scan examples/malicious-pkg-v1 \
  --out "$WORKDIR/baseline-manifests/handy-color-utils@2.3.0.json"

echo
echo "== Step 2: establish the reviewed baseline =="
node bin/capsurface.js baseline "$WORKDIR/baseline-manifests" \
  --out "$WORKDIR/capsurface.lock.json"

echo
echo "== Step 3: scan the compromised point release (2.3.1) =="
node bin/capsurface.js scan examples/malicious-pkg-v2 \
  --out "$WORKDIR/current-manifests/handy-color-utils@2.3.1.json"

echo
echo "== Step 4: run the CI gate =="
set +e
node bin/capsurface.js check "$WORKDIR/current-manifests" --baseline "$WORKDIR/capsurface.lock.json"
code=$?
set -e

echo
if [ "$code" -ne 0 ]; then
  echo "Demo result: capsurface correctly FAILED the check (exit $code), escalation caught."
else
  echo "Demo result: UNEXPECTED: capsurface passed when it should have failed."
  exit 1
fi
