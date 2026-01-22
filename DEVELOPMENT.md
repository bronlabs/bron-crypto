# Development

## Prerequisites

- Go `1.25` (see [go.mod](./go.mod) for the exact minimum)
- C/C++ toolchain (tested with GCC but clang should work too)
- `cmake` and `ninja` (used to build BoringSSL)
- `git` (used to vendor BoringSSL)
- `docker` (optional - if you want to regenerate code, test vectors, or run build and tests in an isolated container)

## Quick start

1. Install dependencies listed above.
2. Build BoringSSL and compile the repo:

```bash
make build
```

This builds BoringSSL under `thirdparty/boringssl/` and then compiles all Go packages with the correct CGO flags.

## BoringSSL setup (required for CGO code)

This repo links against a vendored BoringSSL build (static `libcrypto.a`). The Makefile drives the setup:

```bash
make build-boringssl
```

What this does:

- Clones BoringSSL at the pinned tag into `thirdparty/boringssl/`
- Builds `libcrypto.a` with `cmake` + `ninja`
- Outputs to `thirdparty/boringssl/build/`

If you want to be able to run test or benchmark targets locally in your IDE of choice (or CLI), the correct `CGO_CFLAGS`
and `CGO_LDFLAGS` should be set to link against the correct BoringSSL build (see `build` or `test` targets
in the [Makefile](./Makefile) for reference).

## Build, test, lint

All targets automatically inject the required CGO flags for BoringSSL:

```bash
make build
make test
make bench
make lint
```

See [TESTING.md](./TESTING.md) for guidance on adding unit tests.

## Output artifacts

This repo does not produce a distributable binary or library artifact. It is intended to be used via its Go
packages in other projects rather than as a standalone installable library.

## Code generation (optional)

Some packages use `go generate` (and a few generators shell out to Docker) to generate code and test vectors.
Run `make generate` if for some reason you want to regenerate all code.

Notable generators in this repo:

- [tools/secparams-codegen](./tools/secparams-codegen/): regenerates security parameter tables (`pkg/base/constants.go`).
- [tools/field-codegen](./tools/field-codegen/): regenerates finite field arithmetic (via Fiat Crypto) used by several curves).
- `pkg/base/algebra/impl/fields/vectors/*`: runs SageMath in Docker to regenerate field test vectors.

If you do not have Docker installed, generators that rely on it will fail; keep this in mind when modifying code
that uses `//go:generate` directives (especially the SageMath vector generators).

## Docker-based workflow (optional)

If you want a clean, reproducible toolchain, use the provided helper script to run most targets in an isolated container:

```bash
./run-in-docker.sh make <build|test|bench|lint>
```

This builds a container from [build.Dockerfile](./build.Dockerfile), mounts the repo at `/src`, and sets `BUILD_PREFIX=docker-`
so the BoringSSL build stays separate from the host build. None of the intermediate artifacts are shared between
the host and container builds, and this is by design to avoid polluting the host filesystem and to have consistent
builds across platforms.
