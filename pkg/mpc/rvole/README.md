# `rvole`: OT-Based Random Vector OLE

This package implements the random vector oblivious linear evaluation of
[DKLs23](https://eprint.iacr.org/2023/765), Protocol 5.2, realising the functionality
$F_{RVOLE}(q, ℓ)$ of its Functionality 5.1: Alice inputs $a ∈ Z_q^ℓ$ and receives $c$,
Bob receives a random $b ∈ Z_q$ and $d$, with $c_i + d_i = a_i · b$ for every $i$. It is
the multiplication step of DKLs23 signing.

The package is the OT-agnostic core: it consumes $ξ$ random OTs whose outputs are keys
and turns them into the correlation. The OTs come from one of two subpackages, see
"Instantiations" below: `softspoken` runs them as one `ot/extension/softspoken`
extension over 128 base OTs, `mrr21` runs them directly as `ot/base/mrr21` base OTs
with 256-bit messages.

The parameters follow Variant III of [Asharov26](https://eprint.iacr.org/2026/976),
which keeps the structure of DKLs23 and repairs its analysis, and they also satisfy
the tighter bound of [DoernerRoy26](https://eprint.iacr.org/2026/654) for the same
issue; see "Issues addressed" below.

## Protocol

Bob is the OT receiver and Alice the OT sender. Both run on the same two-party session
as the OTs, so the session transcript binds the whole OT exchange before the rVOLE
starts.

```
Alice (a ∈ Z_q^ℓ)                                       Bob
                                                        g = H(sid, ℓ, ξ) ∈ Z_q^ξ    (both)
                   <==== ξ random OTs, see Instantiations ====>
                                                        Choose: β ∈ {0,1}^ξ the choice bits,
Multiply: both keys k_j^0, k_j^1 of OT j                  k_j the received key of OT j
  α_j^c = PRG(k_j^c) ∈ Z_q^{ℓ+ρ}                          γ_j = PRG(k_j) ∈ Z_q^{ℓ+ρ}
  c_i = −Σ_j g_j α^0_{j,i}                                output b = ⟨g, β⟩
  â <- Z_q^ρ
  ã_j = α_j^0 − α_j^1 + (a ‖ â)
  θ = transcript(…, ã) ∈ Z_q^{ℓ×ρ}
  η_k = â_k + Σ_i θ_{i,k} a_i
  μ = H(α̂^0 + Σ_i θ_{i,k} α^0_{j,i})
                       ---- ã, η, μ ---->                Finish: θ = transcript(…, ã)
                                                          d̃_j = γ_j + β_j ã_j
                                                          check μ against d̃, η, θ
                                                          output d_i = Σ_j g_j d̃_{j,i}
```

- **Random OTs.** The ξ random OTs have random choice bits that are Bob's $β$; DKLs23
  samples $β$ uniformly, so no derandomisation is needed. Each OT output key, 128 bits
  from the extension or 256 bits from the base OTs, is expanded by cSHAKE256 into
  the ℓ + ρ field elements of its row, so one choice bit governs a whole row by construction, which is the $F_{EOTE}(Z_q^{ℓ+ρ}, ξ)$ model the
  DKLs23 proof assumes.
- **Gadget vector.** $g$ is derived from the session identifier and the parameters
  ℓ, ξ alone, on a standalone transcript, before any message is exchanged: Variant
  III's "g fixed at the onset" (Asharov26, Theorem B.17, $g = RO(sid)$), the common
  reference string of DKLs23 Protocol 5.2, footnote a, with the number of OTs raised
  accordingly. Neither party can influence it; in particular it does not depend on
  the OT messages, even when the OTs ran earlier on the same session, since a gadget
  that Alice could grind through her messages would put her in Asharov26's Variant II
  game without its extra 2κ OTs. Bob therefore knows $b$ as soon as his OTs complete,
  which is what DKLs23 signing needs for $ψ = φ − χ$ in the same round as its own
  Alice messages.
- **Consistency check.** The challenge $θ$ is extracted from the transcript after $ã$
  is bound to it, and that transcript already holds every OT message: the base-OT
  messages and, for the extension, its columns and check responses. Bob recomputes
  $μ$ from his rows and aborts if it differs, with an identifiable abort attributed to
  Alice. The check is evaluated for all rows before deciding.
- **Parameters.** $ρ = 1$ masking column. $ξ$ is computed in `NewSuite` from the
  field's bit length and the library's statistical parameter $s$ = 80 as the least
  $m ≥ \log q + 7s + 2\log_2(s+1) + 2s\log_2(e·m/s)$ (Asharov26, Theorem B.17),
  rounded up to a multiple of 128: 1792 for 256-bit fields, 1408 at $s$ = 60 as in
  the paper's Table 1. `NewSuite` rejects fields with $\log q < κ + 2\log ξ$, the
  condition under which $ρ = 1$ suffices (Asharov26, Claim B.8).

### Messages and outputs

The core's only message is `MultiplyMessage`: $ã ∈ Z_q^{ξ×(ℓ+ρ)}$, $η ∈ Z_q^ρ$ and the
256-bit digest $μ$, validated by `Bob.ValidateMultiply` for sender, dimensions,
element presence and field membership. The OT messages belong to the instantiations.
`Bob.Choose` takes the choice bits and received keys and returns $b$; `Alice.Multiply`
takes the key pairs and $a$ and returns the message and $c$; `Bob.Finish` verifies the
message and returns $d$.

## Instantiations

Both subpackages wrap the core in numbered rounds, carry the OT messages and the
`MultiplyMessage` in their own message types, and take a `Suite` from this package.

|                | `softspoken`                                                        | `mrr21`                                                   |
|----------------|---------------------------------------------------------------------|-----------------------------------------------------------|
| OTs            | one `Extend(ξ)` of `ot/extension/softspoken`                     | ξ `ot/base/mrr21` OTs in one round trip, no extension  |
| Setup          | κ = 128 base OTs run earlier on the same session, roles reversed    | none                                                      |
| OT output      | 128-bit key, cSHAKE256 expansion                                    | 256-bit key, cSHAKE256 expansion                          |
| Rounds         | Bob → Alice → Bob (three rounds, two messages)                      | Alice ∥ Bob → Alice → Bob (three rounds, three messages)  |
| Cost at ℓ = 2  | about 16 ms for both parties on an M4 Max                           | about 1.1 s, dominated by the ξ POPF evaluations          |
| Used by        | `dkls23/signing/softspoken`                                                | `dkls23/signing/mrr21`         |

Either source satisfies the assumption of the DKLs23 proof: Protocol 5.2 is proven in
the $F_{EOTE}$ hybrid, the endemic OT of MR19 in which a corrupt party may pick its
own outputs, which the SoftSpokenOT extension and the MRR21 base OT both realise.
Asharov26's §4.5 attack on that hybrid needs a corrupt Alice to choose her outputs
after seeing $θ$; in both instantiations her outputs are fixed by messages that are
in the transcript before $θ$ is extracted. The notes specific to each OT are in the
subpackage READMEs.

## Issues addressed

The 2026 follow-ups to DKLs23 that concern the rVOLE raise the problems below; the
signing-layer issues are handled in `dkls23/signing`.

- **$ξ$ is too small in DKLs23 (Asharov26 §4.4, §5.3; DoernerRoy26 §1.3–1.5).** The
  gadget $g$ is public before the OTs run, and a malicious Alice can fix bits of $β$
  through selective failure on the $μ$ check as a function of $g$; DKLs23's Claim 6.10
  applied the leftover hash lemma as if the seed were uniform, which it then is not.
  Asharov26 bounds the loss with a union bound over constraint sets (Claim 5.7) and
  needs $ξ ≥ 1408$ at $s$ = 60; DoernerRoy26 analyse the inner-product extractor
  under seed-adaptive oblivious bit fixing directly and need only $ξ = 454$ at
  $µ$ = 256, $s$ = 80 (Table 1.5), showing that DKLs23's original $ξ = 416$ already
  gives 69.8 bits. This package uses Asharov26's bound, 1792 at $s$ = 80, which
  satisfies both with a margin; switching to DoernerRoy26's 454, rounded to 512,
  would cut the OTs and $ã$ by 3.5× at the same security level and is a one-line
  change in `suite.go`.
- **$θ$ must bind the OT transcript (Asharov26 §4.5).** In the endemic-OT hybrid a
  corrupt Alice who derives $θ$ from $ã$ alone can choose her OT outputs afterwards
  and cancel the check completely. Here $θ$ is a transcript extraction that includes
  every OT message, the countermeasure Asharov26 recommend; the OT outputs are fixed
  by that transcript before $θ$ exists.
- **$ρ = ⌈\log q/κ⌉ = 2$ is a typo (Asharov26 §4.4).** $ρ = 1$ suffices whenever
  $\log q ≥ κ + 2\log ξ$, enforced in `NewSuite`; $ã$ has ℓ + 1 columns.
- **One choice bit per row.** Earlier implementations ran ξ·(ℓ+ρ) independent
  OTs with the choice bits repeated, so a malicious Bob could pick a different bit
  per column, which $F_{RVOLE}$ cannot express. Deriving every row from one OT output
  removes the gap.

## Differences from DKLs23 Protocol 5.2

- $ξ$ and $ρ$ as above; DKLs23 has $ξ = κ + 2s$ and $ρ = 2$ for 256-bit fields.
- $θ$ and $μ$ are extracted from the session transcript rather than from a random
  oracle applied to $ã$ alone, so they bind the OT exchange.
- The OT outputs are keys expanded into field elements rather than elements of
  $Z_q^{ℓ+ρ}$ drawn by the functionality; the rows are pseudorandom at the key's
  level, 128 bits for the extension, which is the computational level of the whole
  stack.
- Aborts caused by Alice's message are identifiable and attributed to her.

## References
<!-- paper[DKLs23]: docs/papers/2023-765_20231214_215030.pdf [Functionality 5.1; Protocol 5.2; Section 6, Claim 6.10] -->
- [DKLs23] Jack Doerner, Yashvanth Kondi, Eysa Lee, abhi shelat, "Threshold ECDSA in
  Three Rounds", IEEE S&P 2024, [eprint 2023/765](https://eprint.iacr.org/2023/765):
  the functionality (5.1), the protocol (5.2) and its proof (Section 6).
<!-- paper[Asharov26]: docs/papers/2026_976_20260517.pdf [Sections 4.2, 4.4, 4.5, 5.3; Theorem 4.4; Theorem B.17; Claim 5.7; Claim B.8; Table 1] -->
- [Asharov26] Gilad Asharov, "Revisiting DKLs Threshold ECDSA: Enhanced OT-based VOLE
  and Two-Party Signing", [eprint 2026/976](https://eprint.iacr.org/2026/976): the
  three VOLE variants, Variant III (Section 4.4, Theorem B.17) whose parameters this
  package uses, the endemic-OT attack and its countermeasure (Section 4.5), and
  $ρ = 1$ (Claim B.8).
<!-- paper[DoernerRoy26]: docs/papers/2026_654_20260615.pdf [Sections 1.3, 1.4, 1.5; Table 1.5; Section 3.3] -->
- [DoernerRoy26] Jack Doerner, Lawrence Roy, "Tighter Bounds for the Oblivious
  Bit-Fixing Inner Product Extractor on Biased Seeds",
  [eprint 2026/654](https://eprint.iacr.org/2026/654): the seed-adaptive bit-fixing
  bug in the DKLs OLE proof and the tight number of extra OTs that repairs it
  (Table 1.5, Section 1.5), which the parameters here satisfy.

The endemic OT definition (MR19) is cited in `ot/base/mrr21/README.md`.
