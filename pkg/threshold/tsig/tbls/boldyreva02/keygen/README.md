# keygen

Shard creation for Boldyreva threshold BLS signatures.

## Overview

This package converts distributed key generation (DKG) output into threshold BLS shards that can be used for signing.

## Functions

- `NewShortKeyShard` - Creates a shard for short key variant (small public keys, large signatures)
- `NewLongKeyShard` - Creates a shard for long key variant (large public keys, small signatures)

## Usage

```go
// After completing a Gennaro DKG protocol
dkgOutput := // ... from DKG

// Create a short key shard
shard, err := keygen.NewShortKeyShard[P1, FE1, P2, FE2, E, S](dkgOutput)
```
