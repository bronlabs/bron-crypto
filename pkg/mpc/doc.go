// Package mpc provides base types shared across multi-party computation
// protocols built on MSP-based Feldman VSS. It defines [BasePublicMaterial]
// (MSP + verification vector) and [BaseShard] (public material + private
// Feldman share) which concrete protocol packages (DKG, signing, etc.) embed
// to avoid duplicating public-key derivation and serialisation logic.
package mpc
