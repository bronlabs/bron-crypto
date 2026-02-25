// Package gennaro provides distributed key generation for threshold signatures following the Gennaro et al. construction. Each party acts as a dealer for a Pedersen VSS, proves well-formedness with batch Schnorr proofs, and aggregates Feldman verification vectors into the joint public key. The protocol implements Gennaro et al., “Secure Distributed Key Generation for Discrete-Log Based Cryptosystems”.
//
// See README.md for details.
package gennaro
