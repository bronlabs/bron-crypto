// Package signing_softspoken implements DKLs23 threshold ECDSA signing
// (eprint 2023/765, Protocol 3.6) with the random VOLE run over the
// SoftSpokenOT extension (pkg/mpc/rvole/softspoken) on MRR21 base OTs
// (pkg/ot/base/mrr21) that are run inside the session. The signing-layer
// steps and the aggregators come from the parent package.
//
// The paper's three rounds assume the base OTs are preprocessed. Running them
// inside the session costs one extra round, because the MRR21 receiver's
// message does not depend on the sender's:
//
//  1. Base OTs in both directions of every pair, sent simultaneously, plus the
//     commitment to R_i (the paper's round 1 commitment, moved earlier).
//  2. Bob's rVOLE message to every counterparty (the paper's round 1 sample).
//  3. Alice's rVOLE message, the opening of R_i, pk_i, Γ^u, Γ^v and ψ (the
//     paper's round 2).
//  4. The checks and the partial signature (u_i, w_i) (the paper's round 3).
//
// Per ordered pair (Alice, Bob) the base OT, the extension and the rVOLE run
// on one pairwise sub-session, so the rVOLE challenge binds the whole OT
// transcript as Asharov (eprint 2026/976, Section 4.5) requires.
package signing_softspoken
