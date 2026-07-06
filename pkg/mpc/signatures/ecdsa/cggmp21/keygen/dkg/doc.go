// Package dkg implements the auxiliary-information generation of CGGMP21
// (Figure 7), the phase that equips an existing threshold ECDSA key sharing with
// the per-party Paillier and ring-Pedersen material that presigning needs.
//
// It is run after the secret key has been shared (it consumes an mpc.BaseShard
// produced by, e.g., the Canetti DKG). It deliberately implements only the
// auxiliary-information half of Figure 7; the key-refresh / share-rerandomisation
// half is omitted and is provided separately by the redistribute protocol.
//
// Each party runs four rounds:
//
//  1. Sample a Paillier secret key N_i and ring-Pedersen parameters
//     (N̂_i, s_i, t_i), prove the latter well-formed (Π_prm), draw a rid share,
//     and broadcast a hash commitment to all of it.
//  2. Broadcast the opening of that commitment.
//  3. Verify every opening and Π_prm proof, combine the rid shares into a shared
//     rid = ⊕_j rid_j, and send a Paillier-Blum modulus proof (Π_mod) plus a
//     per-verifier no-small-factor proof (Π_fac, bound to the recipient's
//     ring-Pedersen setup).
//  4. Verify all Π_mod and Π_fac proofs and output the base shard augmented with
//     the agreed auxiliary information (a cggmp21.Shard).
//
// Security notes: the round-1 commit-then-reveal binds each party's contribution
// before the openings are seen, so a rushing party cannot adapt its keys or rid
// share to the honest ones; the shared rid is folded into the proof contexts as
// a fresh, jointly random domain separator; and every verification failure
// aborts identifiably, tagging the offending party. The proofs achieve at least
// base.ComputationalSecurityBits of soundness over IFC-length (base.IFCKeyLength)
// moduli; range parameters follow CGGMP21 §C.1.
package dkg
