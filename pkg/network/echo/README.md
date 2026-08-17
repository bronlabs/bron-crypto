# Echo Broadcast

Three-round echo broadcast primitive that ensures all honest parties deliver the same payload.
Suitable for small-group MPC setups where parties can afford two rounds of echo to detect inconsistencies.

## Protocol

1. **Round 1**: each party unicasts its message to everyone.
2. **Round 2**: parties echo a SHA3-256 digest of every payload they observed back to all others.
3. **Round 3**: parties check every echoed digest against the payload they received in round 1; mismatches abort. Validated messages are decoded and returned.

## Notes

- Payloads are CBOR-encoded between rounds to keep the transport generic.
- Round 2 echoes per-sender digests rather than full payloads, so echo traffic stays `O(n² · 32B)` instead of `O(n² · |payload|)`; collision resistance of SHA3-256 preserves the consistency guarantee.
- Quorum membership must include the caller’s `sharing.ID`; otherwise construction fails.
- Correlation IDs separate concurrent broadcasts on the same router.
