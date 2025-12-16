# Network Primitives

Utilities for coordinating multi-party protocols: session identifiers, message routing, and simple exchange patterns. The package is transport-agnostic; callers provide a `Delivery` implementation.

## Overview

- **Session IDs**: `SID` hashes arbitrary inputs to a 32-byte identifier for protocol scoping.
- **Routing**: `Router` wraps a `Delivery` to add correlation IDs, buffering, and quorum awareness.
- **Round helpers**: aliases for `RoundMessages`, `OutgoingUnicasts`, and `Quorum` simplify MPC code.
- **Message exchange**: `ExchangeUnicastSimple` sends per-recipient payloads and waits for responses with matching correlation IDs.
- **Subpackages**: `exchange` combines broadcast + unicast flows; `echo` implements a three-round echo broadcast; `testutils` provides in-memory transports and helpers.

## Key Types

- `Delivery`: user-supplied transport with `Send`/`Receive`, `PartyId`, and `Quorum`.
- `Router`: correlation-aware shim over a `Delivery`; buffers unrelated messages for later retrieval.
- `Runner`: interface for protocol executors (`Run(rt *Router)`).
- `SID`: 32-byte session identifier derived via SHA3-256 over user-provided blobs.

## Typical Flow

1. Implement `Delivery` (or use `testutils.MockCoordinator`) for your environment.
2. Create a `Router` with `NewRouter(delivery)`.
3. Exchange messages with `SendTo`/`ReceiveFrom` or use helpers like `ExchangeUnicastSimple`.
4. Compose more complex protocols via runners that accept a `*Router`.

## Notes

- Messages are CBOR-encoded inside the helpers; callers pass strongly typed payloads.
- Correlation IDs distinguish concurrent exchanges on the same transport.
- Deprecated identity/PKI helpers remain for backward compatibility and will be removed.
