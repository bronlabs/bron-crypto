# lindell22

Implementation of the Lindell 2022 threshold Schnorr signing protocol.

## Overview

This package implements the threshold Schnorr signing protocol from [Yehuda Lindell's 2022 paper](https://eprint.iacr.org/2022/374). The protocol provides:

- 3-round interactive signing
- Identifiable abort (malicious parties can be identified)
- Security in the random oracle model (uses hash-based commitments)

## Security Note

Lindell22 is proven to be secure in standard model only if a UC-secure commitment scheme is used. Since such schemes require trusted setup, we use hash-based commitments for efficiency, relying on the random oracle model.

## Subpackages

- `keygen/` - Key generation from DKG output
- `signing/` - Interactive signing protocol
