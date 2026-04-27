// Package pedersen implements Pedersen commitments in two flavours:
//
//   - Prime-order group: classical Pedersen over a prime-order group with
//     scalars in the group's scalar field. Commitments are perfectly hiding
//     and computationally binding under the discrete-log assumption.
//
//   - CGGMP21 ring-Pedersen: Pedersen over the unknown-order quadratic
//     residue subgroup QR(N̂) of an RSA modulus N̂ = pq. Hiding is
//     statistical (with witnesses sampled from a range exceeding ord(t) by
//     a statistical security parameter) and binding reduces to the strong-RSA
//     assumption, provided messages stay well within ord(t) ≈ N̂/4.
//
// Both flavours expose the same Scheme/Committer/Verifier surface and an
// EquivocableScheme variant that retains the trapdoor λ such that h = g^λ.
// A holder of λ can equivocate any commitment to any message via Trapdoor.Equivocate.
//
// Range checks. Range checks on Message and Witness are not optional: in the
// ring-Pedersen flavour they enforce the message bit-bound ℓ that anchors the
// strong-RSA reduction and the statistical-hiding range for the witness; in
// the prime-group flavour they verify membership in the scalar field.
//
// See README.md for the security argument and constructor-level guidance on
// choosing the message bit-bound and modulus size.
package pedersen
