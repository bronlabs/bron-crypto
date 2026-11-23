// Package softspoken implements the random OT extension of Figure 10 of
// Keller, Orsini and Scholl, "Actively Secure OT Extension with Optimal
// Overhead" (CRYPTO 2015, eprint 2015/546, revised 2022), the simple
// instantiation of Roy's SoftSpokenOT that fixes the original KOS15 consistency
// check. On top of the semi-honest IKNP03 extension (F_COTe) it adds:
//
//   - a consistency check over F_{2^128}: the receiver extends ℓ + 128 OTs with
//     random choice bits, the challenge χ ∈ F_{2^128}^m is derived from the
//     transcript after the IKNP columns are bound to it, the receiver answers
//     with the universal-hash values x̄, t̄¹..t̄^κ, and the sender verifies
//     q̄ⁱ = t̄ⁱ + Δ_i·x̄ for every i, which bounds a malicious receiver's errors
//     as in SoftSpokenOT (Roy, CRYPTO 2022, Fig. 9) with k_C = 1. Deriving χ by
//     Fiat–Shamir, with the statistical parameter raised to κ, is the
//     one-message SoftSpokenOT of DKLs23 (eprint 2023/765, Section 5.1); see
//     check.go;
//   - the randomisation step: the ℓ correlated rows are hashed with
//     H(j, x) = cSHAKE256(j ‖ x) under a salt extracted from the transcript
//     after the columns and the responses are bound to it, the random oracle
//     of DKLs23 Section 5.1, giving the random OT outputs v_{0,j} = H(j, q_j),
//     v_{1,j} = H(j, q_j ⊕ Δ) for the sender and v_{x_j,j} = H(j, t_j) for the
//     receiver; see randomiser.go.
//
// The protocol is fixed to κ = 128: 128 base OTs with 128-bit seeds, 128-bit
// rows and Δ, and 128-bit output messages (Message). The result is a maliciously secure random 1-out-of-2 OT
// extension with receiver choice bits chosen at random; an input-choice OT is
// obtained by the usual derandomisation (KOS15 Figure 9).
package softspoken
