# Network Primitives

Utilities for coordinating multi-party protocols: session identifiers, message routing, and simple exchange patterns. The package is transport-agnostic; callers provide a `Delivery` implementation.

## Overview

- **Session IDs**: `SID` hashes arbitrary inputs to a 32-byte identifier for protocol scoping.
- **Routing**: `Router` wraps a `Delivery` to add correlation IDs, buffering, and quorum awareness.
- **Round helpers**: aliases for `RoundMessages`, `OutgoingUnicasts`, and `Quorum` simplify MPC code.
- **Message exchange**: `SendUnicast`/`ReceiveUnicast` handle per-recipient payloads with matching correlation IDs.
- **Subpackages**: `exchange` combines broadcast + unicast flows; `echo` implements a three-round echo broadcast; `testutils` provides in-memory transports and helpers.

## Key Types

- `Delivery`: user-supplied transport with context-aware `Send`/`Receive`, `PartyID`, and `Quorum`. `Send` must be safe for concurrent use; `Receive` is only called from the router's single reader goroutine.
- `Router`: correlation-aware shim over a `Delivery`; a single reader demultiplexes incoming messages into per-correlation-ID mailboxes, so concurrent exchanges on distinct correlation IDs are safe. `Namespaced` views let parallel runs of one protocol share a delivery; call `Close` when done with the router.
- `Runner`: interface for protocol executors (`Run(ctx context.Context, rt *Router, notificationCallback NotificationCallback)`).
- `SID`: 32-byte session identifier derived via SHA3-256 over user-provided blobs.

## Typical Flow

1. Implement `Delivery` (or use `testutils.MockCoordinator`) for your environment.
2. Create a `Router` with `NewRouter(delivery)`.
3. Exchange messages with `SendTo`/`ReceiveFrom` or use helpers like `SendUnicast`/`ReceiveUnicast`, passing the caller's context.
4. Compose more complex protocols via runners that accept a `*Router`; run concurrent protocol instances over one delivery via `Namespaced` views.
5. `Close` the router once the session is over.

## Notes

- Messages are CBOR-encoded inside the helpers; callers pass strongly typed payloads.
- Correlation IDs distinguish concurrent exchanges on the same transport.
- Deprecated identity/PKI helpers remain for backward compatibility and will be removed.
