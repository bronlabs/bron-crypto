# Lindell17 DKG

DKG for threshold ECDSA following [Lindell et al. “Fast Secure Two-Party ECDSA Signing”](https://eprint.iacr.org/2017/552).
The protocol splits each Shamir share into `x'` and `x''`, commits to the corresponding points,
and uses Paillier plus LP/LPDL proofs to bind encrypted shares to the public key.

## Protocol Outline
-  Commit to `Q' = x'G` and `Q'' = x''G`.
-  Open commitments and prove knowledge of `x'`, `x''`.
-  Generate Paillier keys, encrypt `x'`, `x''`, and start LP/LPDL proofs.
-  Complete LP/LPDL proofs ensuring correct Paillier keys and encryptions.
-  Verify proofs and assemble the final Lindell17 shard (base share + Paillier aux data).

## Implementation Notes

- Hash-based commitments derive CRS from the session id and transcript label.
- LP/LPDL proofs run pairwise with shared transcripts for consistency.
- Errors are standardized via `errs2` sentinels in `errors.go`.

## Usage

1. Instantiate with `NewParticipant(sid, shard, curve, prng, nic, tape)`.
2. Execute `Round1` through `Round8`, exchanging messages with the other party via `network.Router`.
3. The final `Round8` output is a `lindell17.Shard` containing the ECDSA share and Paillier auxiliary info.
