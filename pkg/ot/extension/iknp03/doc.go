// Package iknp03 implements the OT extension of Ishai, Kilian, Nissim and
// Petrank, "Extending Oblivious Transfers Efficiently" (CRYPTO 2003), in its
// correlated form: from κ base OTs with 128-bit messages it produces, per
// extension, l correlated OTs where the sender holds (q_j, Δ) and the receiver
// holds q_j ⊕ x_j·Δ for its choice bit x_j. The rows q_j and Δ are κ bits long,
// so κ is fixed by the output message type M: 128 base OTs for Message128,
// 256 for Message256.
//
// SECURITY: THIS IS A SEMI-HONEST PROTOCOL. It realises the correlated OT with
// errors functionality F_COTe (Keller, Orsini and Scholl, "Actively Secure OT
// Extension with Optimal Overhead", CRYPTO 2015, Figure 2), not correlated OT
// proper: the extension has no consistency check, so a malicious receiver can
// use a different choice vector in every column (the "errors") and, once the
// outputs are used, learn bits of the sender's Δ through selective failure.
// The guarantees against a malicious sender are those of the base OTs only.
// Any use against active adversaries must add a consistency check on top, as
// KOS15 or SoftSpokenOT do, and must hash the outputs with a correlation-robust
// hash before using them as random OTs.
package iknp03
