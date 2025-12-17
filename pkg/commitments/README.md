# Commitments

Interfaces and utilities for commitment schemes plus concrete hash-based and Pedersen implementations.

## Overview

- Core interfaces: `Committer`, `Verifier`, `Scheme`, and `ReRandomisableCommitment`.
- Generic helpers allow swapping in different schemes while keeping a consistent API.
- Subpackages:
  - `hash`: simple HMAC-based commitments over random nonces.
  - `pedersen`: homomorphic Pedersen commitments over prime-order groups.

## Key Concepts

- `Message`: plaintext being committed.
- `Witness`: randomness that hides the message.
- `Commitment`: the resulting binding/hiding value.
- `Scheme`: bundles the committer, verifier, and key/CRS.

## Usage

1. Pick a scheme and construct it with its key/CRS.
2. Obtain a `Committer` via `scheme.Committer()` and call `Commit` (or `CommitWithWitness`).
3. Verify using `scheme.Verifier().Verify(commitment, message, witness)`.
4. For schemes that support it, use `ReRandomise` to reblind commitments without changing the message.
