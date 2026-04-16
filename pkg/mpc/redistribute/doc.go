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
// See README.md for details.
package redistribute
