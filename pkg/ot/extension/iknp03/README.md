# `iknp03`: IKNP Correlated OT Extension (semi-honest)

This package implements the OT extension of
[IKNP03](https://doi.org/10.1007/978-3-540-45146-4_9) (Section 3, Figure 1) in its
correlated form: from κ base OTs it produces, per extension, l correlated OTs where
the sender holds rows $q_j$ and a global correlation $Δ$ and the receiver holds
$q_j ⊕ x_j·Δ$ for its choice bit $x_j$. It is the inner layer of the `softspoken`
extension and is not meant to be used on its own.

**SECURITY: THIS IS A SEMI-HONEST PROTOCOL.** It realises the correlated OT *with
errors* functionality $F_{COTe}$ of [KOS15](https://eprint.iacr.org/2015/546)
(Figure 2), not correlated OT proper. The extension has no consistency check, so a
malicious receiver can use a different choice vector in every column, the "errors",
and, once the outputs are used, learn bits of the sender's $Δ$ through selective
failure. The guarantees against a malicious sender are those of the base OTs only.
Any use against active adversaries must add a consistency check on top, as KOS15 or
SoftSpokenOT do, and must hash the outputs with a correlation-robust hash before
using them as random OTs; `softspoken` does both.

## Protocol

The roles are reversed with respect to the base OTs: the extension **sender** is the
base-OT receiver and the extension **receiver** is the base-OT sender. The number of
base OTs κ is fixed by the output message type M of `ot`, since the rows and $Δ$
are κ bits long: 128 base OTs for `Message128`, 256 for `Message256`. The base-OT
messages are always 128-bit seeds (`Seed = ot.Message128`), the input of one
cSHAKE256 PRG each.

```
Receiver (base-OT sender: k_i^0, k_i^1)              Sender (base-OT receiver: Δ_i, k_i^{Δ_i})

Extend(x ∈ {0,1}^l):
  t_i^0 = PRG(k_i^0), t_i^1 = PRG(k_i^1)   (l bits each)
  u_i = t_i^0 ⊕ t_i^1 ⊕ x                   ---- u_1..u_κ ---->   t_i = PRG(k_i^{Δ_i})
  keep t_i^0                                                       q_i = Δ_i·u_i ⊕ t_i = t_i^0 ⊕ Δ_i·x
transpose: row j of [t_1^0 … t_κ^0]                               transpose: row j of [q_1 … q_κ]
output t_j                                                         output (q_j, Δ),  q_j = t_j ⊕ x_j·Δ
```

- **Seeds and PRG.** Each base-OT message seeds one `PRG`, cSHAKE256 with the seed
  as input and the branch bit and base-OT index as customisation string, for the
  life of the participant; every `Extend` squeezes the next l bits of every stream,
  so successive extensions use disjoint output and both parties must run the same
  extensions in the same order. This is the "small additional cost" of IKNP03
  Section 3, footnote 4: a PRG turns κ base OTs of κ-bit seeds into the $ot^m_k$ the
  figure consumes. cSHAKE256 on a uniform secret seed is a PRG in the random-oracle
  model, which the extension built on top assumes anyway; no paper is cited for it.
- **Columns.** The receiver sends $u_i = t_i^0 ⊕ t_i^1 ⊕ x$ for every base OT, l bits
  each; l must be a positive multiple of 64 and at most `MaxExtension` = 2²⁰. The
  sender forms $q_i = Δ_i·u_i ⊕ t_i$, which equals $t_i^0 ⊕ Δ_i·x$.
- **Transposition.** Both parties transpose their κ × l bit matrix in 64 × 64 blocks
  with the recursive block-swap method of [Chou17](https://eprint.iacr.org/2017/793)
  (Section 3, "Transposing Bit Matrices", Figure 2) into l rows of κ bits, which are
  the output messages.
- **Transcript.** Both parties append the columns $u_1..u_κ$ to the session transcript
  at every extension, so a check built on top can derive its challenge from them.
- **Untransposed columns.** `Extend` also returns the untransposed columns, $t_i^0$ on
  the receiver's side and $q_i$ on the sender's, which the consistency check of
  `softspoken` hashes column by column.

### Outputs

The receiver obtains a `ot.ReceiverOutput[M]` with its choice bits and rows $t_j$;
the sender a `ot.SenderCorrelatedOutput[M]` with the rows $q_j$ and $Δ$, whose
second message of OT j is $q_j ⊕ Δ$. $Δ$ is the sender's base-OT choice vector and is
the same for every extension by design; it and the seeds must stay secret.

## Differences from the paper

- Only the correlation step of IKNP03 Figure 1 is implemented. The paper's final step,
  where the sender encrypts its inputs under $H(j, q_j)$ and $H(j, q_j ⊕ s)$, is left to
  the layer above: `softspoken` hashes the rows into random OT messages and
  derandomises them if needed. In KOS15's terms this package is steps 1–4 of the
  Extend phase of Figure 10.
- The paper assumes a semi-honest receiver; this package offers no protection beyond
  that and says so. The fully secure variant of IKNP03 Section 4 (Figure 2,
  cut-and-choose) is not implemented; the consistency check of `softspoken` plays
  that role.
- Base OTs are the endemic OT of `mrr21` rather than the ideal $ot^k_k$ of the paper;
  see `mrr21/README.md` for why endemic base OTs suffice for extension.
- The columns are bound to the session transcript, which the paper does not need.

## References
<!-- paper[IKNP03]: docs/papers/978-3-540-45146-4_9.pdf [Section 3, Figure 1; Section 3.1, Lemma 1; Section 1.3] -->
- [IKNP03] Yuval Ishai, Joe Kilian, Kobbi Nissim, Erez Petrank, "Extending Oblivious
  Transfers Efficiently", CRYPTO 2003, [DOI 10.1007/978-3-540-45146-4_9](https://doi.org/10.1007/978-3-540-45146-4_9):
  the extension with a semi-honest receiver (Section 3, Figure 1), its security
  (Section 3.1) and the correlation-robustness requirement on the hash (Section 1.3,
  Lemma 1).
<!-- paper[KOS15]: docs/papers/2015-546_20220916_035217.pdf [Figure 2; Figure 10, Extend steps 1–4] -->
- [KOS15] Marcel Keller, Emmanuela Orsini, Peter Scholl, "Actively Secure OT Extension
  with Optimal Overhead", CRYPTO 2015, revised 2022, [eprint 2015/546](https://eprint.iacr.org/2015/546):
  the correlated OT with errors functionality $F_{COTe}$ this package realises
  (Figure 2) and the seed-expanded formulation of the IKNP columns that the code
  follows (Figure 10, Extend steps 1–4).
<!-- paper[Chou17]: docs/papers/2017-793.pdf [Section 3, "Transposing Bit Matrices"; Figure 2] -->
- [Chou17] Tung Chou, "McBits Revisited", CHES 2017,
  [eprint 2017/793](https://eprint.iacr.org/2017/793): the in-place 64 × 64 bit-matrix
  transposition by recursive block swaps (Section 3, Figure 2) that `transpose64`
  implements, verified by the round-trip tests of `transpose_test.go`.
