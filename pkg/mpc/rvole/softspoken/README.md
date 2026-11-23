# `rvole_softspoken`: Random Vector OLE over SoftSpokenOT

This package instantiates the random vector OLE core of `mpc/rvole` with the
random OT extension of `ot/extension/softspoken`: the $ξ$ OTs of one rVOLE are one
`Extend(ξ)` call over κ = 128 base OTs run earlier on the same session, with 128-bit
outputs. It is the instantiation `dkls23/signing/softspoken` uses.

## Protocol

Bob is the extension receiver and holds the base-OT sender output; Alice is the
extension sender and holds the base-OT receiver output. Both are constructed from
those outputs on the session the base OTs ran on, so the transcript holds the base-OT
messages before the extension's challenge and the rVOLE's θ are derived; the gadget
$g$ depends on the session identifier only.

```
Alice (a ∈ Z_q^ℓ)                                        Bob
                                                         Round1: Extend(ξ): β the random
                     <---- Round1P2P: extension ----       choice bits, k_j the outputs;
Round2: Extend on the message, consistency                 Choose → b
  check, abort attributed to Bob on failure;
  Multiply(a) on the ξ output pairs → c
                     ---- Round2P2P: ã, η, μ ---->       Round3: Finish → d, abort
                                                           attributed to Alice on failure
```

- `Round1P2P` carries the `softspoken.RoundExtendP2P` and is validated, on top of the
  extension's own checks, for exactly $ξ$ OTs. `Round2P2P` carries the core's
  `MultiplyMessage`.
- `NewAlice(ctx, suite, baseOTReceiverOutput, prng)` and
  `NewBob(ctx, suite, baseOTSenderOutput, prng)` take the outputs of κ base OTs with
  `Message128` outputs, for example `ot/base/mrr21`, run with the roles reversed.
- `Alice.Round2` checks that $a$ has exactly ℓ entries before running the extension:
  the extension advances the sender's PRG state, so a bad input must not consume it.

## Security notes

- **Endemic outputs.** The extension's outputs are endemic in the sense of MR19:
  Alice's are fixed by her Δ and Bob's columns, Bob's by his seeds. That is the
  $F_{EOTE}$ hybrid of the DKLs23 proof, and $θ$ is extracted after the columns and
  the check responses are in the transcript, which closes Asharov26's §4.5 attack; see
  the core README.
- **Consistency check.** The SoftSpokenOT check makes the extension maliciously secure;
  the residual selective-failure leakage on Alice's Δ is the one the SoftSpokenOT proof
  tolerates, see the extension's README. In `dkls23/signing/softspoken` the base OTs, and so Δ, are
  fresh per signing session.
- **Hash.** The extension randomises its outputs with cSHAKE256 salted from the
  transcript after the columns and the check responses are bound to it, so the keys
  the rows are expanded from are random-oracle outputs bound to the whole OT exchange.
- **Cost.** Bob's message holds 128 columns of $ξ$ + 128 bits each, 30 KiB at
  $ξ$ = 1792, plus the check responses; Alice's message is $ξ·(ℓ+1)$ field elements.
  `BenchmarkRVOLE` measures one ℓ = 2 rVOLE.

## References
<!-- paper[DKLs23]: docs/papers/2023-765_20231214_215030.pdf [Protocol 5.2; Section 5.1] -->
- [DKLs23] Jack Doerner, Yashvanth Kondi, Eysa Lee, abhi shelat, "Threshold ECDSA in
  Three Rounds", IEEE S&P 2024, [eprint 2023/765](https://eprint.iacr.org/2023/765):
  the protocol (5.2) and its treatment of the OT extension (Section 5.1).
<!-- paper[Asharov26]: docs/papers/2026_976_20260517.pdf [Section 4.5] -->
- [Asharov26] Gilad Asharov, "Revisiting DKLs Threshold ECDSA: Enhanced OT-based VOLE
  and Two-Party Signing", [eprint 2026/976](https://eprint.iacr.org/2026/976): the
  endemic-OT attack and its countermeasure (Section 4.5).

The extension and its references (KOS15, SoftSpokenOT, DKLs23) are documented in
`ot/extension/softspoken/README.md`; the core, its parameters and the remaining
references in `mpc/rvole/README.md`.
