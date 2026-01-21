#!/usr/bin/env bash
BRON_CRYPTO_HOME=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
docker run --platform=linux/amd64 --rm -v "${BRON_CRYPTO_HOME}:/src/" -e BUILD_PREFIX="ubuntu-" "$(docker build --platform=linux/amd64 -q -f "${BRON_CRYPTO_HOME}/ubuntu.Dockerfile" "${BRON_CRYPTO_HOME}")" "$@"
