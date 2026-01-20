# Testing

## Test types

- Unit tests: functional correctness.
- Property tests: randomized invariants (see `pgregory.net/rapid` usage in tests).
- Benchmarks: performance.

## Quick commands

```bash
make test
make test-race
make bench
make coverage
```

These targets build BoringSSL and inject the required CGO flags automatically.

## Package-specific tests

If you want to run a subset of tests directly with `go test`, you must pass the
same CGO flags used in the Makefile so the BoringSSL headers and static library
are found. Example:

```bash
CGO_CFLAGS="-I$(pwd)/thirdparty/boringssl/include" \
CGO_LDFLAGS="-L$(pwd)/thirdparty/boringssl/build -lcrypto" \
go test ./pkg/hashing/...
```

If you built with a `BUILD_PREFIX` (for example, the Docker workflow uses
`docker-`), update the build path accordingly:
`thirdparty/boringssl/${BUILD_PREFIX}build`.

## Benchmarks

Run all benchmarks:

```bash
make bench
```

Run benchmarks for a subset:

```bash
CGO_CFLAGS="-I$(pwd)/thirdparty/boringssl/include" \
CGO_LDFLAGS="-L$(pwd)/thirdparty/boringssl/build -lcrypto" \
go test ./pkg/hashing/... -bench=. -run=^$
```

## Coverage

Run coverage for all packages:

```bash
make coverage
```

This writes `coverage.out` in the repo root. To view an HTML report:

```bash
go tool cover -html=coverage.out -o coverage.html
```
