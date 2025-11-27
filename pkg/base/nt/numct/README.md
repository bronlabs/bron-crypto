# numct

Package `numct` provides constant-time arbitrary-precision arithmetic for cryptographic applications.

## Overview

This package wraps [saferith](https://github.com/cronokirby/saferith) and [boringssl](https://github.com/google/boringssl) to provide `Nat` (natural numbers), `Int` (signed integers), and `Modulus` types. All arithmetic, except possibly some for even moduli, avoids secret-dependent branches and memory access patterns, making it suitable for use in cryptographic protocols where timing side-channels must be avoided.

## Architecture

The package has two implementations of modular arithmetic:

- **`ModulusBasic`**: Pure Go implementation using saferith. Portable and works everywhere.
- **`Modulus`**: CGO-accelerated implementation using BoringSSL's bignum for modular exponentiation and inversion on odd moduli. Falls back to `ModulusBasic` for even moduli or when CGO is disabled.

The CGO implementation provides significant performance improvements for expensive operations like modular exponentiation while maintaining identical constant-time semantics. Build with `purego` or `nobignum` tags to use the pure Go implementation exclusively.

## Key Types

- **`Nat`**: Unsigned arbitrary-precision integer with constant-time operations.
- **`Int`**: Signed arbitrary-precision integer built on `Nat`.
- **`Modulus`**: Represents a modulus and provides modular arithmetic operations (add, sub, mul, div, exp, inv, sqrt).

## Usage Notes

- All comparison operations return `ct.Bool` or `ct.Choice` types that can be used for constant-time conditional operations.
- Use `Select` and `CondAssign` for constant-time branching based on secret values.
- The `Modulus` type caches Montgomery context for repeated exponentiations with the same modulus.
