// Package signing_mrr21 implements DKLs23 threshold ECDSA signing (eprint
// 2023/765, Protocol 3.6) with the random VOLE run directly on MRR21 base OTs
// with 256-bit messages (pkg/mpc/rvole/mrr21), without an OT extension. The
// signing-layer steps and the aggregators come from the parent package.
//
// Because the two round-1 messages of the one-round-trip base OT are
// independent, the protocol keeps the paper's three rounds with the OTs run
// inside the session:
//
//  1. The commitment to R_i and, to every counterparty, both base-OT
//     messages: Alice's m_S of the pair where this party is Alice and Bob's
//     POPFs of the pair where it is Bob.
//  2. Bob's rVOLE output χ, then Alice's rVOLE message, the opening of R_i,
//     pk_i, Γ^u, Γ^v and ψ (the paper's round 2).
//  3. The checks and the partial signature (u_i, w_i) (the paper's round 3).
//
// Per ordered pair (Alice, Bob) the base OTs and the rVOLE run on one
// pairwise sub-session, so the rVOLE challenge binds the whole OT transcript
// as Asharov (eprint 2026/976, Section 4.5) requires. It costs about ten
// times the SoftSpokenOT instantiation, since every row of the rVOLE is a
// public-key operation.
package signing_mrr21
