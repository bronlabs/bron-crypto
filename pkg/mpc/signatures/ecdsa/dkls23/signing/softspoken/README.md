# `dkls23/signing/softspoken`: DKLs23 Signing over SoftSpokenOT

This package instantiates DKLs23 signing, Protocol 3.6 of
[DKLs23](https://eprint.iacr.org/2023/765), with the random VOLE of
`mpc/rvole/softspoken`: the SoftSpokenOT extension of `ot/extension/softspoken` on
the one-round-trip base OTs of `ot/base/mrr21`, both run inside the session. The
signing-layer steps, the aggregators and the references are in the parent package
`dkls23/signing`; this package provides the cosigner, the messages, the rounds and the
runner. It is the instantiation to use unless OT extensions are ruled out.

The runner executes four rounds. On success each party receives a `SignResult` with
its own partial signature and a session-bound aggregator.

## Protocol flow

The paper's three rounds assume preprocessed base OTs. Running them inside the
session costs one extra round, because the MRR21 receiver's message does not depend
on the sender's. For every ordered pair $(i, j)$ the parties run one rVOLE in which
$P_i$ is Alice and $P_j$ is Bob, on its own pairwise sub-session; $P_i$ is the base-OT
receiver of that pair and $P_j$ the base-OT sender, since the extension reverses the
roles.

1. **Base OTs and commitment.** $P_i$ commits to $R_i = r_i·G$ (`Core.Commit`) and
   broadcasts the commitment. To every $P_j$ it sends both MRR21 round-1 messages
   at once: as base-OT sender in the pair where it is Bob, as base-OT receiver with
   random choice bits in the pair where it is Alice.
2. **Bob's multiplication message.** $P_i$ completes both base OTs of every pair,
   builds the rVOLE participants and sends Bob's message of each; it now knows its
   random inputs $χ_{i,j} = b$ (the paper's round 1 sample).
3. **Alice's multiplication message and openings.** $P_i$ answers every rVOLE as
   Alice with input $(r_i, sk_i)$ and sends $Γ^u_{i,j}$, $Γ^v_{i,j}$ and $ψ_{i,j}$;
   it broadcasts the opening of $R_i$ and $pk_i$ (the paper's round 2).
4. **Checks and partial signature.** $P_i$ opens every $R_j$, finishes every rVOLE
   as Bob, verifies the check equations and the public key, and outputs the partial
   signature $(R, u_i, w_i)$ (the paper's round 3). Failed checks are identifiable
   aborts attributed to the counterparty, as are rVOLE and extension aborts.

## Transcript binding

Each pairwise sub-session carries the base-OT messages, the extension columns and
check responses, and the rVOLE's $ã$, in that order, so the extension's Fiat–Shamir
challenge and the rVOLE challenge are bound to everything exchanged in that pair.

## Differences from DKLs23

- One extra round for the in-session base OTs; with preprocessed base OTs the
  protocol is the paper's three rounds.
- The commitment to $R_i$ is sent in round 1 together with the base-OT messages,
  earlier than the paper's round 1 sample; the opening, $pk_i$, $Γ$ and $ψ$ stay
  together in the round of Alice's message, as in the paper's round 2.
- The differences shared with the other instantiation are listed in
  `dkls23/signing/README.md`.

## References

See `dkls23/signing/README.md` for DKLs23, Segev26 and Asharov26, and the READMEs of
`ot/base/mrr21`, `ot/extension/softspoken` and `mpc/rvole/softspoken` for the OT and
rVOLE layers.
