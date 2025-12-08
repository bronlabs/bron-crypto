# num

Package `num` provides arbitrary-precision arithmetic for cryptographic applications. It is built over the constant-time `numct` package and is suitable for high-level applications.

## Overview

This package provides immutable, strongly-typed number representations that implement standard algebraic interfaces. Unlike `numct`, operations in `num` are not constant-time—use `numct` directly when timing side-channels must be avoided.

## Key Types

- **`NatPlus`** (`NPlus()`): Positive natural numbers (excludes zero).
- **`Nat`** (`N()`): Natural numbers (non-negative integers).
- **`Int`** (`Z()`): Signed integers.
- **`Rat`** (`Q()`): Rational numbers (fractions).
- **`Uint`** / **`ZMod`**: Integers modulo n. Implements `algebra.ZModLike`.

## Architecture

Each numeric type has an associated structure type (e.g., `NaturalNumbers`, `Integers`, `Rationals`, `ZMod`) accessible via singleton functions (`N()`, `Z()`, `Q()`, `NewZMod()`). These structures provide constructors, constants, and implement algebraic interfaces from the `algebra` package.

All types wrap `numct` primitives internally and provide:
- Conversion to/from `*big.Int` and `*big.Rat`
- CBOR serialization
- Hash codes for use in maps and sets
- Random sampling within ranges

## Usage Notes

- Types are immutable; all operations return new values.
- Use `Canonical()` on `Rat` to reduce fractions to lowest terms.
- `ZMod` caches Montgomery context for efficient modular arithmetic.
- Random sampling uses half-open intervals `[low, high)`.
