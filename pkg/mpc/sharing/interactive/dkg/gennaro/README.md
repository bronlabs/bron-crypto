# Gennaro DKG

Distributed key generation for threshold signatures following the Gennaro et al. construction.
Each party acts as a dealer for a Pedersen VSS, proves well-formedness with batch Schnorr proofs,
and aggregates Feldman verification vectors into the joint public key.
The protocol implements [Gennaro et al., “Secure Distributed Key Generation for Discrete-Log Based Cryptosystems”](https://link.springer.com/content/pdf/10.1007/s00145-006-0347-3.pdf).

## Protocol Overview

1. **Pedersen Deal**: Everyone deals a Pedersen VSS instance and broadcasts the verification vector.
2. **Feldman Lift**: Dealers privately send Pedersen shares, 
   lift the dealer polynomial into the exponent, and broadcast a Feldman verification vector with a batch Schnorr proof.
3. **Verify & Aggregate**: Parties verify proofs and shares; all Feldman vectors and shares are added
   to form the final secret share and public key material.

## Implementation Notes

- Pedersen commitments provide hiding shares; Feldman vectors back up public verification.
- Batch Schnorr proofs bind each dealer’s Feldman vector to their Pedersen dealer function.
- `Participant` exposes `Round1`, `Round2`, `Round3`; use a `network.Router` or the provided runner to shuttle messages.

## Usage

1. Construct a `Participant` via `NewParticipant` (or `NewGennaroDKGRunner` for orchestration).
2. Run `Round1` and exchange `Round1Broadcast` messages.
3. Run `Round2` with received broadcasts; exchange `Round2Broadcast` and `Round2Unicast`.
4. Run `Round3` with collected inputs to obtain `DKGOutput`, containing the private share and public material.
