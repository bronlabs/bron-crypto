// Package intcom implements the bounded integer (ring-Pedersen) commitment scheme
// of CGGMP21. A commitment to an integer message m with integer randomness r is
// C = sᵐ·tʳ mod N̂, where s and t generate QR(N̂) in an RSA group of unknown order
// and log_t(s) is unknown. Binding is computational, under the factoring /
// discrete-log assumption in QR(N̂); hiding is statistical, because the witness is
// drawn from a range far wider than the (hidden) group order. Messages are
// committed over the integers, which is what supports range proofs over the
// committed value. A TrapdoorKey holding λ = log_t(s) and the modulus
// factorisation can equivocate, as needed in simulation-based proofs.
//
// See README.md for details.
package intcom
