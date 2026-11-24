# `dkls23/signing`: DKLs23 Signing

This package and its subpackages implement DKLs23 threshold ECDSA signing from
[DKLs23](https://eprint.iacr.org/2023/765), Protocol 3.6, with the output step of
the refined protocol of [Segev26](https://eprint.iacr.org/2026/929), which restores
the statistical security DKLs23 claimed. Shards, partial signatures and the
key-generation adapter are shared with the `dkls23` package.

This package holds what every instantiation shares; the subpackages instantiate the
protocol with one of the random VOLEs of `mpc/rvole`:

- `softspoken` (imported as `signing_softspoken`): the rVOLE over the SoftSpokenOT
  extension on MRR21 base OTs run inside the session, four rounds.
- `mrr21` (imported as `signing_mrr21`): the rVOLE directly on MRR21 base OTs with
  256-bit messages and no extension, the paper's three rounds, at about ten times the
  cost.

Both expose the same shape: a `Cosigner` with numbered rounds, a `NewRunner` that
returns a `SignResult`, and the aggregators of this package. The protocol flows are
in the subpackage READMEs.

## Shared parts

- **`Core`** holds the signing-layer state and the steps of Protocol 3.6 that do not
  depend on the rVOLE, called by an instantiation in the paper's order:
  `Commit` extracts the commitment key from the transcript, samples the instance key
  $r_i$ and the inversion mask $φ_i$ and commits to $R_i = r_i·G$;
  `ReceiveCommitment` and `ReceiveChi` record a counterparty's commitment and Bob's
  rVOLE output $χ_{i,j}$; `AliceInput` derives the additive key share
  $sk_i$ with the zero-sharing mask and returns $(r_i, sk_i)$; `CheckValues` turns
  Alice's rVOLE output $(c^u_{i,j}, c^v_{i,j})$ into $Γ^u_{i,j} = c^u_{i,j}·G$,
  $Γ^v_{i,j} = c^v_{i,j}·G$ and $ψ_{i,j} = φ_i − χ_{i,j}$; `Opening` returns the
  opening of $R_i$ with $pk_i = sk_i·G$; `ReceiveOpening` verifies a counterparty's
  opening; `Verify` checks Bob's rVOLE output $(d^u_{i,j}, d^v_{i,j})$ against
  $χ_{i,j}·R_j − Γ^u_{j,i} = d^u_{i,j}·G$ and $χ_{i,j}·pk_j − Γ^v_{j,i} = d^v_{i,j}·G$;
  and `Finish` checks $Σ_k pk_k = pk$, sets $R = Σ_j R_j$ with $r_x$ its x-coordinate,
  computes

  $u_i = r_i(φ_i + Σ_j ψ_{j,i}) + Σ_j (c^u_{i,j} + d^u_{i,j})$,
  $v_i = sk_i(φ_i + Σ_j ψ_{j,i}) + Σ_j (c^v_{i,j} + d^v_{i,j})$,
  $w_i = H(m)·φ_i + r_x·v_i$

  and returns the partial signature $(R, u_i, w_i)$. A failed opening or check is an
  identifiable abort attributed to the counterparty; a failed public-key check is not
  attributable.
- **Validators** `ValidateCommitment`, `ValidateOpening` and `ValidateCheckValues` are
  shared by the instantiations' message types.
- **Aggregators**, below, and **`SignResult`**, the runners' output: this party's
  partial signature and the session-bound aggregator.

## Aggregation

`SignResult.PartialSignature` returns the local partial signature.
`SignResult.PartialSignatureCosigningAggregator` returns an aggregator bound to the
successful session, also available as `NewCosigningAggregator` on the `Core` of a
cosigner that has produced its partial signature. `NewNonCosigningAggregator` builds a
stateless aggregator for a party outside the session from the suite, the public key
and the message.

Both aggregators compute $s = (Σ_i w_i)(Σ_i u_i)^{-1}$ and perform the two output
checks of Segev26's refined protocol (Step 4), which DKLs23 lacks:

- **Nonce consistency (Step 4a).** Every partial signature must carry the same
  aggregated nonce point $R$. The cosigning aggregator compares against the $R$ it
  computed itself and attributes a mismatch to the sender; the non-cosigning one
  can only check that all partial signatures agree with each other. Without this
  check an unbounded adversary can commit to a different $R_{1,j}$ towards each
  honest party and craft per-party shares so that honest parties output different
  valid signatures with different nonces (Segev26, Section 4).
- **Sign consistency (Step 4c).** The cosigning aggregator verifies
  $R = s^{-1}H(m)·G + s^{-1}r_x·pk$ against its own $R$, so a share that yields $−s$
  is rejected rather than accepted as the valid signature on $−R$. Both aggregators
  then normalise to low-s, the alternative Segev26 allows, which makes the output
  canonical, and verify the signature under the public key (Step 4e).

A cosigning aggregator can be used once: aggregation consumes the session state.

## Transcript binding

Run [session setup](../../../../session/README.md) for every signing run and pass the
resulting `session.Context` to `NewCosigner` or `NewRunner`. Its pairwise seeds are used
to derive that run's zero shares.

The signing transcript starts with the instantiation's domain separator and the
session identifier; the commitment key is extracted from it in round 1. Every pairwise
sub-session, derived by `Core.PairContext` for an ordered pair (Alice, Bob), carries
that pair's OT messages and the rVOLE's $ã$, so the rVOLE challenges and checks are
bound to everything exchanged in that pair, the countermeasure of Asharov26
Section 4.5.

## Differences from DKLs23

- The rVOLE uses Variant III of Asharov26 rather than the paper's parameters; see
  `mpc/rvole/README.md`.
- The output step adds Segev26's nonce- and sign-consistency checks; the paper's
  fragments $(w_i, u_i)$ are extended with $R$ for the first of them.
- Zero shares come from the session's pairwise seeds (DKLs23's $F_{Zero}$ with
  pre-shared seeds) rather than Segev26's setup-free relaxed zero sharing.
- Failure handling stops at the identifiable abort; the paper's blacklisting of a
  pair after a failed rVOLE and its pipelining and presigning modes are not
  implemented.
- The round structure of each instantiation is described in its README.

## References
<!-- paper[DKLs23]: docs/papers/2023-765_20231214_215030.pdf [Protocol 3.6; Functionality 5.1; Protocol 5.2; Section 5.1] -->
- [DKLs23] Jack Doerner, Yashvanth Kondi, Eysa Lee, abhi shelat, "Threshold ECDSA in
  Three Rounds", IEEE S&P 2024, [eprint 2023/765](https://eprint.iacr.org/2023/765):
  the signing protocol (Protocol 3.6) and the multiplication functionality it uses
  (Functionality 5.1, Protocol 5.2).
<!-- paper[Segev26]: docs/papers/2026_929_20260511.pdf [Section 3, the refined protocol; Section 4, the split-view and sign attacks] -->
- [Segev26] Gil Segev, "On the Statistical vs. Computational Security of the DKLs23
  Multiparty ECDSA Protocol", [eprint 2026/929](https://eprint.iacr.org/2026/929): the
  split-view attack showing DKLs23 is not statistically secure as claimed, and the
  refined protocol whose nonce-consistency and sign-consistency checks the
  aggregators implement.
<!-- paper[Asharov26]: docs/papers/2026_976_20260517.pdf [Section 4.4; Section 4.5; Section 6] -->
- [Asharov26] Gilad Asharov, "Revisiting DKLs Threshold ECDSA: Enhanced OT-based VOLE
  and Two-Party Signing", [eprint 2026/976](https://eprint.iacr.org/2026/976): the
  rVOLE variants, of which Variant III is used here because it keeps the round
  count of the multi-party protocol, and the transcript-binding countermeasure.
