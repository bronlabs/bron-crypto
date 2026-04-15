// Package redistribute provides a three-round protocol for verifiable share
// redistribution between a qualified set of existing holders and a new access
// structure.
//
// Previous shareholders first run an interactive zero-sharing subprotocol, then
// publish and distribute contributions that let next shareholders assemble fresh
// shares of the same secret. Inconsistencies in the old metadata are checked
// against a designated trusted dealer to support identifiable aborts.
//
// The protocol follows the verifiable redistribution approach of Wong and Wing,
// adapted to the HJKY zero-sharing, Feldman-style verification, and MSP-based
// sharing abstractions used in this repository.
//
// See README.md for details.
package redistribute
