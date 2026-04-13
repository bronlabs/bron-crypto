# tbls

Threshold BLS signature scheme implementation for pairing-friendly curves.

## Overview

This package provides the core types for threshold BLS signatures, where a group of parties collectively hold shares of a secret key and can produce signatures that are valid under a single public key.

## Features

- Supports both short key (G1 public keys, G2 signatures) and long key (G2 public keys, G1 signatures) variants

## Subpackages

- `boldyreva02` - Boldyreva threshold BLS signature protocol implementation
