// Package signing implements the signing phase of DKLs23 threshold ECDSA
// (eprint 2023/765, Protocol 3.6). It holds what every instantiation shares:
// the Core with the signing-layer state and steps of Protocol 3.6 (the
// commitment to the instance key R_i, the additive key share, the check
// values Γ^u, Γ^v and ψ, the final checks and the partial signature), the
// partial-signature aggregators with the output checks of Segev (eprint
// 2026/929), and the SignResult the runners return.
//
// The protocol is instantiated by the subpackages, which own the OTs, the
// random VOLEs, the messages and the rounds and call into the Core in the
// order of the paper: softspoken runs the rVOLE over the SoftSpokenOT
// extension on MRR21 base OTs in four rounds, mrr21 runs it directly on
// MRR21 base OTs with 256-bit messages in the paper's three rounds.
package signing
