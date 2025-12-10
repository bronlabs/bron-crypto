# znstar

Package `znstar` provides multiplicative groups of units modulo n, denoted (Z/nZ)*, for cryptographic applications such as RSA and Paillier encryption.

## Overview

This package implements the group of invertible elements (units) in the ring Z/nZ. An element is a unit if and only if it is coprime to the modulus n. The package provides two concrete instantiations:

- **RSA Groups**: Units modulo n = p·q where p, q are large primes
- **Paillier Groups**: Units modulo n² where n = p·q

Both group types support known-order and unknown-order variants. Known-order groups use the factorization to enable efficient operations via the Chinese Remainder Theorem, while unknown-order groups work with only the public modulus.

## Key Types

### RSA Groups
- **`RSAGroupKnownOrder`**: RSA group with known factorization (p, q). Uses CRT-accelerated arithmetic.
- **`RSAGroupUnknownOrder`**: RSA group with only the public modulus n.
- **`RSAGroupElementKnownOrder`** / **`RSAGroupElementUnknownOrder`**: Elements of the respective groups.

### Paillier Groups
- **`PaillierGroupKnownOrder`**: Paillier group with known factorization. Supports `Representative`, `NthResidue`, and `EmbedRSA` operations.
- **`PaillierGroupUnknownOrder`**: Paillier group with only the public modulus n².
- **`PaillierGroupElementKnownOrder`** / **`PaillierGroupElementUnknownOrder`**: Elements of the respective groups.

### Interfaces
- **`UnitGroup[U]`**: Interface for multiplicative groups of units with random sampling, hashing, and serialization.
- **`Unit[U]`**: Interface for group elements with multiplication, exponentiation, and inversion.

## Architecture

The package uses Go generics with a trait-based design:

- **`UnitGroupTrait`**: Shared implementation for group operations (sampling, hashing, serialization).
- **`UnitTrait`**: Shared implementation for element operations (multiplication, exponentiation, inversion).

Arithmetic operations are delegated to the `modular` package, which provides:
- **`OddPrimeFactors`**: CRT-based arithmetic for known factorization (RSA).
- **`OddPrimeSquareFactors`**: CRT-based arithmetic for n² with known factorization (Paillier).
- **`SimpleModulus`**: Generic modular arithmetic for unknown factorization.

## Paillier-Specific Operations

- **`Representative(m)`**: Computes (1 + m·n) mod n², mapping plaintexts to group elements.
- **`NthResidue(u)`**: Computes u^n mod n², used in Paillier decryption.
- **`EmbedRSA(u)`**: Embeds an RSA group element (mod n) into the Paillier group (mod n²).

## Usage Notes

- Minimum prime size is 1024 bits for RSA/Paillier group creation.
- Use `ForgetOrder()` to convert a known-order group/element to unknown-order.
- Use `LearnOrder(knownOrderGroup)` to convert an unknown-order element back when factorization is available.
