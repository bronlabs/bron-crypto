#!/usr/bin/env bash
set -e

BRON_CRYPTO_HOME=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

# Read effective settings, including values persisted with go env -w.
go_env_args=()
for name in GOPROXY GOSUMDB GOPRIVATE GONOPROXY GONOSUMDB; do
    if command -v go > /dev/null 2>&1; then
        value=$(GOTOOLCHAIN=local go env "${name}")
        go_env_args+=(-e "${name}=${value}")
    else
        go_env_args+=(-e "${name}")
    fi
done

image=$(docker build -q -f "${BRON_CRYPTO_HOME}/build.Dockerfile" "${BRON_CRYPTO_HOME}")
docker run --rm -v "${BRON_CRYPTO_HOME}:/src/" -e BUILD_PREFIX="docker-" "${go_env_args[@]}" "${image}" "$@"
