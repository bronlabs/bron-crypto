# boldyreva02

Implementation of the Boldyreva BLS signature scheme over arbitrary monotone access structures.

## Overview

This package implements BLS signatures based on the Boldyreva construction, generalised from simple threshold to arbitrary monotone access structures via MSP-based secret sharing (Karchmer-Wigderson). It provides a simple non-interactive signing protocol where each party produces a partial signature that can be aggregated into a full signature.

## Rogue Key Prevention

Supports three algorithms to prevent rogue key attacks:
- `Basic` - No protection (use only in trusted settings)
- `MessageAugmentation` - Prepends public key to message before signing
- `POP` (Proof of Possession) - Requires parties to prove knowledge of their secret key

## Subpackages

- `keygen` - Shard creation from DKG output
- `signing` - Signing protocol with cosigners and aggregator

## Reference
- [B02]: [Threshold Signatures, Multisignatures and Blind Signatures Based on the Gap-Diffie-Hellman-Group Signature Scheme](https://link.springer.com/chapter/10.1007/3-540-36288-6_3)
