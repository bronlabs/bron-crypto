// Package redistribute provides a three-round protocol for verifiable share
// redistribution between a qualified set of existing holders and a new access
// structure.
//
// Previous shareholders first run an interactive zero-sharing subprotocol, then
// publish and distribute contributions that let next shareholders assemble fresh
// shares of the same secret. A next-only shareholder (one that did not hold a
// previous share) has no local reference for the old metadata, so identifiable
// aborts on old-metadata inconsistencies require it to designate an existing
// previous shareholder as a trusted anchor. The anchor's round-2 message is
// treated as ground truth for those checks: this is an intentional part of the
// trust model, not a soundness gap. Parties that do not wish to extend that
// trust can omit the anchor, in which case old-metadata failures still abort
// the protocol but are not attributed to a specific sender.
//
// The protocol follows the verifiable redistribution approach of Wong and Wing,
// adapted to the HJKY zero-sharing, Feldman-style verification, and MSP-based
// sharing abstractions used in this repository.
//
// Round2 uses a single broadcast to the whole session quorum. That broadcast
// includes old-shareholder public-key material for all previous shareholders,
// including previous verification-vector commitments such as [s_i]G. The
// current design therefore treats every new participant as a consumer of this
// public old-shareholder material, even if a next-only participant did not
// configure a trusted anchor and will not use the material for identifiable
// abort checks.
//
// Redistribution, refresh, and recovery do not erase or revoke previous shares.
// Applications using this package must securely erase obsolete shares and all
// serialised or backed-up copies after a successful protocol run.
//
// See README.md for details.
package redistribute
