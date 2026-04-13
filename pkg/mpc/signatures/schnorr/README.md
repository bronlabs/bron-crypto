# schnorr

MPC Schnorr signature implementation supporting arbitrary monotone access structures and multiple MPC-friendly Schnorr variants.

## Overview

This package provides the core types and interfaces for MPC Schnorr signing, where a signature requires cooperation from a qualified set of parties (as defined by a monotone access structure) holding secret key shares.

## Subpackages

- `lindell22/` - Lindell 2022 signing protocol implementation
