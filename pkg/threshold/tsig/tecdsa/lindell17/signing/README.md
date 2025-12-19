# Lindell17 Signing

Two-party threshold ECDSA signing protocol from [“Fast Secure Two-Party ECDSA Signing”](https://eprint.iacr.org/2017/552).
Uses Paillier homomorphism and Schnorr proofs to combine nonces and shares into a joint signature.

## Protocol Outline

1. Primary commits to nonce `R1`; secondary samples `R2` and proves knowledge of `k2`.
2. Primary verifies `R2`, proves knowledge of `k1`, and both derive `R = k1 * R2`.
3. Secondary verifies `R1`, homomorphically computes `c3` under the primary’s Paillier key, and returns it.
4. Primary decrypts `c3`, derives `s`, and outputs the ECDSA signature `(r, s)` after verification.

## Implementation Notes

- Hash-based commitments derive CRS from session id and transcript label.
- DLog proofs use compiled non-interactive Schnorr protocols.
- Paillier auxiliary data in shards comes from the Lindell17 DKG.
- Errors standardised via `errs2` sentinels in `errors.go`.

## Usage

1. Construct cosigners with `NewPrimaryCosigner` / `NewSecondaryCosigner`.
2. Run `Round1`–`Round5` exchanging messages between the two parties.
3. Primary verifies and returns the final ECDSA signature.
