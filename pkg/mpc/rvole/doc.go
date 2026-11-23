// Package rvole implements the OT-based random vector OLE of DKLs23
// (Doerner, Kondi, Lee, shelat, "Threshold ECDSA in Three Rounds", eprint
// 2023/765, Protocol 5.2) with the parameters of Variant III of Asharov,
// "Revisiting DKLs Threshold ECDSA" (eprint 2026/976, Section 4.4 and Theorem
// B.17):
//
//   - the gadget vector g is fixed from the transcript before the OTs run, as
//     in DKLs23, so the receiver knows b = ⟨g, β⟩ as soon as the OTs complete,
//     and the number of OTs ξ is raised to the bound of Theorem B.17 so that b
//     stays statistically close to uniform against an adversary that fixes
//     constraints on β after seeing g;
//   - one OT per choice bit: the ℓ + ρ field elements of row j are all derived
//     from the single output of OT j, so one choice bit governs the whole row
//     by construction, which is the F_EOTE(Z_q^{ℓ+ρ}, ξ) model the DKLs23 proof
//     assumes;
//   - ρ = 1 masking column, which suffices whenever log q ≥ κ + 2·log ξ;
//   - the challenge θ is derived from a transcript that already binds the OT
//     messages, the countermeasure of Section 4.5.
//
// This package is the OT-agnostic core: Alice masks her input into Bob's rows
// and answers the check, Bob chooses rows and verifies. The OTs are supplied by
// the subpackages: softspoken runs the ξ OTs as one SoftSpokenOT extension over
// 128 base OTs, mrr21 runs them as ξ one-round-trip MRR21 base OTs with 256-bit
// messages and no extension. Alice inputs a ∈ Z_q^ℓ and receives c; Bob
// receives a random b and d with c_i + d_i = a_i·b.
package rvole
