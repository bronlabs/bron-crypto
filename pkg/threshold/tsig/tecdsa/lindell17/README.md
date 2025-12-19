# Lindell17 Threshold ECDSA

Implementation of the Lindell et al. two-party threshold ECDSA protocol from [“Fast Secure Two-Party ECDSA Signing”](https://eprint.iacr.org/2017/552) 
with minor engineering adaptations (non-interactive proofs).

## Components

- Shared helpers: Paillier-backed shard material, partial signatures, decomposition helper.
- Key generation (`keygen/dkg`): two-party DKG building shards with Paillier auxiliary data.
- Signing (`signing`): two-party signing using Paillier homomorphism and Schnorr proofs.

## Notes

- Uses Paillier for homomorphic operations on secret shares, and hash-based commitments for binding messages to sessions.
- Transcript labels/domain separation follow `BRON_CRYPTO_LINDELL17_*` prefixes.
- Error handling is standardized via `errs2` sentinels defined in `errors.go`.

See subpackage READMEs for round-by-round details.
