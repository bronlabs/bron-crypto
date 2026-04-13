# bls

MPC BLS signature scheme implementation for pairing-friendly curves over arbitrary monotone access structures.

## Overview

This package provides the core types for MPC BLS signatures, where a qualified set of parties (defined by a monotone access structure) collectively hold shares of a secret key and can produce signatures that are valid under a single public key.

## Features

- Supports both short key (G1 public keys, G2 signatures) and long key (G2 public keys, G1 signatures) variants

## Subpackages

- `boldyreva02` - Boldyreva BLS signature protocol implementation
