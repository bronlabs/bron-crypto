# `rvole_mrr21`: Random Vector OLE over MRR21 Base OTs

This package instantiates the random vector OLE core of `mpc/rvole` with base OTs
alone: the $ξ$ OTs of one rVOLE are one batch of the one-round-trip endemic OT of
`ot/base/mrr21` with 256-bit messages, and there is no OT extension.

## Protocol

Both round-1 messages are independent of each other, so they travel in the same round,
and both parties complete their OTs in round 2.

```
Alice (a ∈ Z_q^ℓ)                                        Bob
Round1: base-OT sender message m_S                       Round1: β ∈ {0,1}^ξ random,
                     ---- AliceRound1P2P ---->             one POPF programmed on each β_j
                     <---- BobRound1P2P ----
Round2: finish the OTs on the POPFs, both keys           Round2: finish the OTs on m_S,
  k_j^0, k_j^1 per OT, abort attributed to Bob             the key k_j of each OT;
  on a malformed POPF; Multiply(a) → c                     Choose → b
                     ---- AliceRound2P2P: ã, η, μ ---->  Round3: Finish → d, abort
                                                           attributed to Alice on failure
```

- `AliceRound1P2P` carries the `mrr21.SenderRound1P2P`, `BobRound1P2P` the
  `mrr21.ReceiverRound1P2P` with its $ξ$ POPFs, and `AliceRound2P2P` the core's
  `MultiplyMessage`. The round-1 wrappers check the sender and delegate to the base
  OT's own validation.
- `NewAlice(ctx, suite, prng)` and `NewBob(ctx, suite, prng)` need no setup: the base
  OT participants are created inside, for $ξ$ OTs with `Message256` outputs.
- `Alice.Round2` checks that $a$ has exactly ℓ entries before completing the OTs.

## Security notes

- **Endemic OT suffices.** DKLs23 prove Protocol 5.2 in the $F_{EOTE}$ hybrid, the
  endemic OT of MR19 in which a corrupt party may choose its own outputs. MRR21
  realises exactly that functionality for a batch of base OTs (its Theorem 11), so the
  rVOLE's assumption is met without an extension; what the extension removes is cost,
  not a security requirement. Asharov26's §4.5 attack needs Alice to choose her
  outputs after seeing $θ$; here her outputs are determined by her own $m_S$ and Bob's
  POPFs, both in the transcript before $θ$ is extracted.
- **No Δ.** Every OT has independent randomness, so a failed check
  leaks nothing about other OTs beyond the selective failure on $μ$ that $ξ$ accounts
  for, and every output is its own HKDF-SHA256 derivation bound to the session's
  transcript salt. The random-oracle and tagged-KA assumptions are those of the base
  OT's README.
- **256-bit messages.** Each key is expanded by cSHAKE256 into its row, so the rows
  carry the full 256 bits of entropy of the OT output; the key agreement and the field
  keep the protocol's computational level at 128 bits.
- **Cost.** Each party evaluates $ξ$ = 1792 POPFs, about 1.1 s for both parties
  sequentially at ℓ = 2 on an M4 Max against 16 ms for the `softspoken`
  instantiation; `BenchmarkRVOLE` measures it. Bob's message carries
  one POPF per OT, Alice's one group element and then $ã$.

## References
<!-- paper[DKLs23]: docs/papers/2023-765_20231214_215030.pdf [Protocol 5.2; Section 6] -->
- [DKLs23] Jack Doerner, Yashvanth Kondi, Eysa Lee, abhi shelat, "Threshold ECDSA in
  Three Rounds", IEEE S&P 2024, [eprint 2023/765](https://eprint.iacr.org/2023/765):
  the protocol (5.2) and its proof in the endemic-OT hybrid (Section 6).
<!-- paper[Asharov26]: docs/papers/2026_976_20260517.pdf [Section 4.5] -->
- [Asharov26] Gilad Asharov, "Revisiting DKLs Threshold ECDSA: Enhanced OT-based VOLE
  and Two-Party Signing", [eprint 2026/976](https://eprint.iacr.org/2026/976): the
  endemic-OT attack and its countermeasure (Section 4.5).

The base OT and its references (MRR21, MR19) are documented in
`ot/base/mrr21/README.md`; the core, its parameters and the remaining references
in `mpc/rvole/README.md`.
