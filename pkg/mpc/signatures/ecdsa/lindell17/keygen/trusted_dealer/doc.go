// Package trusted_dealer implements MSP-based Lindell17 key generation with a
// trusted dealer. It encrypts raw MSP components without the DKG package's LP
// and LPDL proofs, so the dealer must honestly generate and erase secret
// material.
//
// See README.md for details.
package trusted_dealer
