# trusteddealer

Centralised dealer that generates shares for an arbitrary monotone access structure using Feldman VSS.

## ⚠️ Test-Only Package

**This package must only be used for testing and development.** A trusted dealer is not a distributed key generation protocol — it samples the secret key on a single machine and distributes shares from it. The dealer learns the secret in plaintext, defeating the security guarantees that DKG provides. Any production code that uses `trusteddealer` is broken.

For real distributed key generation, use:

- [`pkg/mpc/dkg/canetti`](../canetti) — a four-round DKG protocol.
- [`pkg/mpc/dkg/gennaro`](../gennaro) — Gennaro-style DKG.

## Overview

The single exported function `Deal` runs Feldman secret sharing over the supplied access structure and returns one `*mpc.BaseShard` per shareholder, all sharing the same verification vector and MSP matrix. The output is suitable for seeding signing protocol tests that need pre-distributed key material without the cost of running a full DKG.

## Usage

```go
import (
    "github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
    "github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
    "github.com/bronlabs/bron-crypto/pkg/mpc/dkg/trusteddealer"
    "github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
)

group := k256.NewCurve()
ac, _ := threshold.NewThresholdAccessStructure(2, shareholders)
shards, _ := trusteddealer.Deal(group, ac, pcg.NewRandomised())
```
