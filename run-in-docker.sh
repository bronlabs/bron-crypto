#!/usr/bin/env bash
BRON_CRYPTO_HOME=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
docker run --rm -v "${BRON_CRYPTO_HOME}:/src/" -e BUILD_PREFIX="docker-" -e GODEBUG="cpu.avx2=off" "$(docker build -q -f "${BRON_CRYPTO_HOME}/build.Dockerfile" "${BRON_CRYPTO_HOME}")" "$@"
