// Package mina implements Schnorr signatures for the Mina Protocol.
//
// Mina uses a Schnorr signature scheme over the Pallas curve (part of the Pasta
// curve cycle) with the Poseidon hash function for challenge computation.
// This signature scheme is used for transaction signing in the Mina blockchain.
//
// # Key Differences from Standard Schnorr
//
//   - Curve: Pallas (part of Pasta cycle, ~255-bit prime field)
//   - Hash: Poseidon algebraic hash over the base field
//   - Message format: ROInput (structured field elements and bits)
//   - Byte order: Little-endian for field elements
//   - Nonce derivation: Deterministic using Blake2b (legacy mode)
//   - R encoding: Only x-coordinate with implicit even y
//
// # Signature Format
//
// A Mina signature is 64 bytes: (R.x || s) in little-endian, where:
//   - R.x: 32-byte x-coordinate of the nonce commitment
//   - s: 32-byte response scalar
//
// The y-coordinate of R is always even (parity 0), enforced during signing.
//
// # Network IDs
//
// Mina uses network-specific prefixes for domain separation:
//   - MainNet: "MinaSignatureMainnet"
//   - TestNet: "CodaSignature*******"
//
// References:
//   - Mina Protocol: https://minaprotocol.com
//   - o1js implementation: https://github.com/o1-labs/o1js
package mina
