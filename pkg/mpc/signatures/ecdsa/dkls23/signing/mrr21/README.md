# `dkls23/signing/mrr21`: DKLs23 Signing over MRR21 Base OTs

This package instantiates DKLs23 signing, Protocol 3.6 of
[DKLs23](https://eprint.iacr.org/2023/765), with the random VOLE of `mpc/rvole/mrr21`:
every row of the rVOLE is one one-round-trip base OT of `ot/base/mrr21` with 256-bit
messages, and there is no OT extension. The signing-layer steps, the aggregators and
the references are in the parent package `dkls23/signing`; this package provides the
cosigner, the messages, the rounds and the runner. It costs about ten times the
`softspoken` instantiation, since every rVOLE row is a public-key operation, and
exists for deployments that rule out OT extensions.

The runner executes three rounds, the paper's own count. On success each party
receives a `SignResult` with its own partial signature and a session-bound
aggregator.

## Protocol flow

The two round-1 messages of the base OT are independent, so in-session base OTs cost
no extra round. For every ordered pair $(i, j)$ the parties run one rVOLE in which
$P_i$ is Alice, the base-OT sender, and $P_j$ is Bob, the base-OT receiver, on its own
pairwise sub-session.

1. **Base OTs and commitment.** $P_i$ commits to $R_i = r_i·G$ (`Core.Commit`) and
   broadcasts the commitment. To every $P_j$ it sends both rVOLE round-1 messages at
   once: Alice's base-OT sender message $m_S$ in the pair where it is Alice, and
   Bob's POPFs on random choice bits in the pair where it is Bob (the paper's round 1).
2. **Multiplication messages and openings.** $P_i$ completes every rVOLE as Bob,
   learning $χ_{i,j} = b$, then answers every rVOLE as Alice with input $(r_i, sk_i)$
   and sends $Γ^u_{i,j}$, $Γ^v_{i,j}$ and $ψ_{i,j}$; it broadcasts the opening of
   $R_i$ and $pk_i$ (the paper's round 2).
3. **Checks and partial signature.** $P_i$ opens every $R_j$, finishes every rVOLE
   as Bob, verifies the check equations and the public key, and outputs the partial
   signature $(R, u_i, w_i)$ (the paper's round 3). Failed checks are identifiable
   aborts attributed to the counterparty, as are rVOLE and base-OT aborts.

## Transcript binding

Each pairwise sub-session carries $m_S$, the POPFs and the rVOLE's $ã$, so the
base-OT key-derivation salt and the rVOLE challenge are bound to everything exchanged
in that pair.

## Differences from DKLs23

- The round structure is the paper's, with the base OTs run inside the session
  instead of preprocessed.
- The differences shared with the other instantiation are listed in
  `dkls23/signing/README.md`.

## References

See `dkls23/signing/README.md` for DKLs23, Segev26 and Asharov26, and the READMEs of
`ot/base/mrr21` and `mpc/rvole/mrr21` for the OT and rVOLE layers.
