# SoftSpoken OT Extension

Package `softspoken` implements a maliciously secure 1-out-of-2 Random Oblivious
Transfer extension (ROT) with 128-bit messages and random choice bits, in one message
from the receiver to the sender per extension, on top of the semi-honest `iknp03`
correlated OT (F_COTe).

We follow the designs from:
- [KOS15](https://eprint.iacr.org/2015/546), Figure 10 (2022 revision), the "simple
  instantiation of SoftSpokenOT", for the protocol description and the notation
  $ROT^{κ,ℓ}$; the whole protocol is that figure.
- [SoftSpokenOT](https://eprint.iacr.org/2022/192), Figure 9, for the consistency
  check, which Figure 10 specialises to $p = q = 2$ and the repetition code
  ($k_C = 1$, $n_C = κ$); see the comment at the top of `check.go` for the mapping of
  Roy's $U, V, W, R$ onto the columns of this package.
- [DKLs23](https://eprint.iacr.org/2023/765), Section 5.1, for the Fiat–Shamir
  transform of the check: the challenge χ is derived from the transcript after the
  receiver's columns are bound to it instead of being sent by the sender, which makes
  the extension one message, and the statistical parameter s of the figure is raised
  to κ because the receiver can brute-force a convenient challenge. The same
  random-oracle model covers the randomisation hash $H$, instantiated with cSHAKE256
  salted from the transcript.

Derandomisation into chosen-message or correlated OT is not part of this package; it
is the usual transformation of KOS15 Figure 9 (and MR19) and is done by the caller.

## Protocol

Both parties are built from the base OTs of `mrr21` run with the roles reversed: the
extension sender is the base-OT receiver and its κ = 128 choice bits are $Δ$; the
extension receiver is the base-OT sender and holds both 128-bit seeds of every base
OT. One `Extend` call produces ℓ random OTs, ℓ a positive multiple of σ = 128 with
ℓ + σ at most `iknp03.MaxExtension`.

Run fresh base OTs for each new extension participant pair. Use each role's
base-OT output to initialise exactly one extension participant. For successive
`Extend` calls, keep the same participant pair so the PRG streams continue, and
run matching calls in the same order on both sides.

```
Receiver                                                       Sender (Δ)

Extend(ℓ):  ℓ' = ℓ + σ, m = ℓ/σ
  x <- {0,1}^ℓ'                      (random choice bits, the last σ only for the check)
  iknp03.Extend(x): columns u_i,      ---- u_1..u_κ ---->      iknp03.Extend: columns q_i,
    rows t_j, keeps t_i = t_i^0                                 rows q_j = t_j ⊕ x_j·Δ
  χ = transcript(…, u_1..u_κ) ∈ F_{2^σ}^m                      χ = transcript(…, u_1..u_κ)
  x̄ = Σ_j x̂_j χ_j + x̂_{m+1}
  t̄^i = Σ_j t̂^i_j χ_j + t̂^i_{m+1}   ---- x̄, t̄^1..t̄^κ ---->    q̄^i = Σ_j q̂^i_j χ_j + q̂^i_{m+1}
                                                                check q̄^i = t̄^i + Δ_i·x̄ for all i
  output x_j, H(j, t_j), j < ℓ                                  output H(j, q_j), H(j, q_j ⊕ Δ), j < ℓ
```

- **Consistency check.** The ℓ' bits of every column are split into m + 1 blocks of
  σ bits read as elements of $F_{2^{128}}$ (`bf128`), and the universal hash
  $h_χ(v̂) = Σ_{j=1}^{m} v̂_j χ_j + v̂_{m+1}$ is applied to x and to every column. The
  last block is random and enters with coefficient 1, so x̄ reveals nothing about the
  first ℓ choice bits, and those σ rows are discarded. A receiver that used different
  choice vectors in different columns passes with probability at most $2^{-σ}$ per
  attempt. The receiver's responses are bound to the transcript after χ is derived.
- **Randomisation.** The surviving ℓ rows are hashed with $H(j, x) = cSHAKE256(j ‖ x)$
  under a 256-bit salt extracted from the transcript after the columns and the
  responses are bound to it, so every output is bound to the session and to the whole
  exchange so far, and no (salt, j) pair repeats across sessions or extensions. The
  two hashes of one OT, on $q_j$ and $q_j ⊕ Δ$, share $j$ by design; that is the
  correlation the notion covers. The output is truncated to the 128-bit `Message`.
- **Messages.** `RoundExtendP2P` carries the `iknp03` columns and the responses x̄ and
  t̄¹..t̄^κ. It validates its origin, the columns (through `iknp03`), that ℓ' is a
  multiple of σ of at least 2σ, and that exactly κ responses are present; the
  responses are parsed as field elements of exactly 128 bits.
- **Aborts and state.** A failed check is an identifiable abort attributed to the
  receiver, evaluated for all columns before deciding. Any failure after the
  `iknp03` extension has run leaves the PRG streams and the transcript ahead of the
  counterparty's, so the participant then refuses every further `Extend`.

### Outputs

The receiver obtains a `ot.ReceiverOutput[Message]` with its ℓ random choice bits
and messages, the sender a `ot.SenderOutput[Message]` with both messages of every
OT, where `Message = ot.Message128`. The package is fixed to κ = 128: 128 base OTs
with 128-bit seeds, 128-bit rows and Δ, and 128-bit outputs.

## Differences from the papers

- χ is derived by Fiat–Shamir from the session transcript (DKLs23 §5.1) rather than
  sent by the sender, and the transcript binds the session and the base OTs as well as
  the columns, a superset of what DKLs23 hash; σ = κ = 128 for the same reason.
- The choice bits are random, as in a random OT; the figure's chosen bits are obtained
  by derandomisation outside this package.
- The abort is identifiable; the figure only says "output Abort".
- The hash key is a fixed constant rather than a per-session value.

## Best-effort constant time

The code of this package is written in a best-effort mode to be constant time:
1. The check compares the sender's values against the receiver's responses with
   `bf128.Select` and `crypto/subtle.ConstantTimeCompare`, folds the verdict over all
   κ columns and aborts only afterwards, so the abort does not reveal which column
   failed.
2. Column arithmetic uses `crypto/subtle.XORBytes`; the field arithmetic of the check
   is that of `bf128`.
3. The PRG and the hash are cSHAKE256; Keccak has no data-dependent branches or
   table lookups, so both are constant time in software.
4. The base OT of `mrr21` is not constant time in the choice bits, which here are Δ;
   see its README.

## References
<!-- paper[KOS15]: docs/papers/2015-546_20220916_035217.pdf [Figure 10; Figure 9; Section 4; "Instantiating the Hash Function"] -->
- [KOS15] Marcel Keller, Emmanuela Orsini, Peter Scholl, "Actively Secure OT Extension
  with Optimal Overhead", CRYPTO 2015, revised 2022,
  [eprint 2015/546](https://eprint.iacr.org/2015/546): the protocol as implemented
  (Figure 10), the universal hash of the check and its instantiation note, the
  derandomisation (Figure 9) left to callers.
<!-- paper[SoftSpokenOT]: docs/papers/2022-192_20251118_195730.pdf [Figure 9; Definition 4.1; Section 4] -->
- [SoftSpokenOT] Lawrence Roy, "SoftSpokenOT: Quieter OT Extension from Small-Field
  Silent VOLE in the Minicrypt Model", CRYPTO 2022,
  [eprint 2022/192](https://eprint.iacr.org/2022/192): the consistency check (Figure 9)
  and the hiding property of the universal hash (Definition 4.1).
<!-- paper[DKLs23]: docs/papers/2023-765_20231214_215030.pdf [Section 5.1] -->
- [DKLs23] Jack Doerner, Yashvanth Kondi, Eysa Lee, abhi shelat, "Threshold ECDSA in
  Three Rounds", IEEE S&P 2024, [eprint 2023/765](https://eprint.iacr.org/2023/765):
  the one-message SoftSpokenOT in the random-oracle model (Section 5.1), the
  Fiat–Shamir transform of the check and the rule s → κ.
