#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
mul_go="$root/pkg/base/algebra/impl/mul.go"

if rg -n 'precomputed\[w\]' "$mul_go"; then
	echo "secret scalar multiplication must not index precomputed tables by scalar windows" >&2
	exit 1
fi

secret_msm="$(awk '
	/^func MultiScalarMulLowLevel\[/ { in_secret = 1 }
	/^func MultiScalarMulLowLevelVartimePublic\[/ { in_secret = 0 }
	in_secret { print }
' "$mul_go")"

if printf '%s\n' "$secret_msm" | rg -n 'buckets\[win\]|if win == 0|IsZero\(\)'; then
	echo "secret multi-scalar multiplication must not branch or index by scalar windows" >&2
	exit 1
fi

