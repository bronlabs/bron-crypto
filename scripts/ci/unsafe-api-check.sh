#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"

if rg -n '"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"' "$root" \
	--glob '*.go' \
	--glob '!**/*_test.go' \
	--glob '!**/testutils/**' \
	--glob '!pkg/base/prng/pcg/**' \
	--glob '!tools/**'; then
	echo "pkg/base/prng/pcg is test-only and must not be imported by production packages" >&2
	exit 1
fi

