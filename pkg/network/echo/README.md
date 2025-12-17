# Echo Broadcast

Three-round echo broadcast primitive that ensures all honest parties deliver the same payload.
Suitable for small-group MPC setups where parties can afford two rounds of echo to detect inconsistencies.

## Protocol

1. **Round 1**: each party unicasts its message to everyone.
2. **Round 2**: parties echo every payload they observed back to all others.
3. **Round 3**: parties check that all echoes match; mismatches abort. Validated messages are decoded and returned.

## Notes

- Payloads are CBOR-encoded between rounds to keep the transport generic.
- Quorum membership must include the caller’s `sharing.ID`; otherwise construction fails.
- Correlation IDs separate concurrent broadcasts on the same router.
