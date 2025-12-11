# modular

Package `modular` provides CRT-accelerated modular arithmetic for cryptographic applications such as RSA and Paillier.

## Overview

This package implements the `Arithmetic` interface for modular operations, with specialized implementations that use the Chinese Remainder Theorem (CRT) for acceleration when the factorization is known. All operations use constant-time arithmetic from the `numct` package.

## Key Types

### SimpleModulus

- **`SimpleModulus`**: Basic modular arithmetic over a single modulus. Used when the factorization is unknown or not applicable.

### OddPrimeFactors (RSA-style)

- **`OddPrimeFactors`**: CRT-accelerated arithmetic modulo n = p·q where p and q are distinct odd primes. Operations are parallelized across the two factors and recombined using CRT.

### OddPrimeSquareFactors (Paillier-style)

- **`OddPrimeSquare`**: Arithmetic modulo p² for a single odd prime p.
- **`OddPrimeSquareFactors`**: CRT-accelerated arithmetic modulo n² = (p·q)² where p and q are distinct odd primes. Used in Paillier encryption.

## Usage Notes

- `MultiBaseExp` computes multiple exponentiations with the same exponent in parallel.
- **`OddPrimeSquareFactors.ExpToN(out, a)`** Computes a^n mod n² slightly more efficiently than plain CRT-based modular exponentiation (used in Paillier)
- All types support CBOR serialization for the `Arithmetic` interface.
