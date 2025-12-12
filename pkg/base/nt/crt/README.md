# crt

Package `crt` provides Chinese Remainder Theorem (CRT) reconstruction and decomposition for cryptographic applications.

## Overview

This package implements CRT operations for reconstructing values from residues modulo pairwise coprime factors. It supports both two-factor CRT (common in RSA) and multi-factor CRT (for generalized applications). All operations use the constant-time arithmetic from the `numct` package.

## Key Types

### Two-Factor CRT

- **`Params`**: Precomputed parameters for CRT recombination with two coprime moduli p and q. Stores q^{-1} mod p for efficient reconstruction.
- **`ParamsExtended`**: Extended parameters that additionally store the moduli as `Modulus` types and support decomposition operations.

### Multi-Factor CRT

- **`ParamsMulti`**: Precomputed parameters for CRT with k pairwise coprime factors. Uses Garner's algorithm for serial reconstruction and lift-based recombination for parallel reconstruction.

## Operations

### Recombination

Reconstruct x from residues (x mod p_i) using:
- **`Recombine(mp, mq, p, q)`**: One-shot reconstruction for two factors
- **`Params.Recombine(mp, mq)`**: Reconstruction using precomputed parameters
- **`ParamsMulti.Recombine(...residues)`**: Multi-factor reconstruction

### Decomposition

Compute residues from a value:
- **`ParamsExtended.Decompose(m)`**: Returns (m mod p, m mod q)
- **`ParamsMulti.Decompose(m)`**: Returns residues for all factors

Both `Decompose` methods automatically choose between serial and parallel execution based on operand size.

## Usage Notes

- Use `Precompute` or `NewParamsMulti` to create reusable parameters when performing multiple CRT operations with the same moduli.
- All factors must be pairwise coprime; creation functions return `ct.False` if this condition is not met.
- For two-factor CRT, `ParamsExtended` provides decomposition while `Params` only supports recombination.
