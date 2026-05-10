#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
makefile="$root/Makefile"

if ! rg -q '^BORINGSSL_COMMIT := [0-9a-f]{40}$' "$makefile"; then
	echo "BoringSSL must be pinned with BORINGSSL_COMMIT := <40-hex-sha>" >&2
	exit 1
fi

if rg -n 'BORINGSSL_TAG|--branch "\$?\{?BORINGSSL_TAG\}?"' "$makefile"; then
	echo "BoringSSL must not be fetched by mutable tag" >&2
	exit 1
fi

if ! rg -q 'rev-parse HEAD' "$makefile"; then
	echo "BoringSSL checkout must verify git rev-parse HEAD against BORINGSSL_COMMIT" >&2
	exit 1
fi

