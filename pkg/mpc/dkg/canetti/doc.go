// Package canetti implements a four-round distributed key generation protocol in
// the style of CGGMP21/Canetti et al., adapted to generic monotone access
// structures expressed through MSP-based Feldman sharing.
//
// Each party samples a fresh dealer function, commits to its opening material,
// privately distributes shares, proves consistency of the verification vector
// with a batch Schnorr proof, and aggregates all accepted contributions into a
// final shard. The resulting shard is an [mpc.BaseShard] backed by the MSP of
// the supplied access structure.
//
// See README.md for protocol details and usage guidance.
package canetti
