package ecdsa

import (
	"crypto"
	"hash"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
)

// Suite encapsulates the cryptographic parameters for an ECDSA instance.
// It binds together the elliptic curve, hash function, and signing mode (randomised
// or deterministic) to ensure consistent parameter usage across signing and verification.
type Suite[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	deterministic bool
	curve         Curve[P, B, S]
	baseField     algebra.PrimeField[B]
	scalarField   algebra.PrimeField[S]
	hashFunc      func() hash.Hash
	hashID        crypto.Hash
}

// NewSuite creates a new ECDSA suite for randomised signing.
// The hash function is used to compute message digests before signing.
//
// Common configurations:
//   - P-256 with SHA-256
//   - P-384 with SHA-384
//   - secp256k1 with SHA-256 (Bitcoin/Ethereum)
func NewSuite[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S], H hash.Hash](curve Curve[P, B, S], hashFunc func() H) (*Suite[P, B, S], error) {
	if hashFunc == nil {
		return nil, ErrInvalidArgument.WithMessage("hash function is nil")
	}
	scalarField := algebra.StructureMustBeAs[algebra.PrimeField[S]](curve.ScalarStructure())
	baseField := algebra.StructureMustBeAs[algebra.PrimeField[B]](curve.BaseStructure())

	s := &Suite[P, B, S]{
		false,
		curve,
		baseField,
		scalarField,
		hashing.HashFuncTypeErase(hashFunc),
		0,
	}
	return s, nil
}

// NewDeterministicSuite creates a new ECDSA suite for deterministic signing per RFC 6979.
//
// Deterministic ECDSA generates the nonce k from the private key and message hash using
// HMAC-DRBG, eliminating the need for a random source during signing. This prevents
// catastrophic nonce reuse vulnerabilities that have affected systems with poor entropy.
//
// The hash parameter must be a registered crypto.Hash that is available on the system.
//
// Reference: RFC 6979 - Deterministic Usage of DSA and ECDSA
func NewDeterministicSuite[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](curve Curve[P, B, S], h crypto.Hash) (*Suite[P, B, S], error) {
	if !h.Available() {
		return nil, ErrFailed.WithMessage("hash function not available")
	}
	scalarField := algebra.StructureMustBeAs[algebra.PrimeField[S]](curve.ScalarStructure())
	baseField := algebra.StructureMustBeAs[algebra.PrimeField[B]](curve.BaseStructure())

	s := &Suite[P, B, S]{
		deterministic: true,
		curve:         curve,
		baseField:     baseField,
		scalarField:   scalarField,
		hashFunc:      h.New,
		hashID:        h,
	}
	return s, nil
}

// IsDeterministic returns true if this suite uses RFC 6979 deterministic nonce generation.
func (s *Suite[P, B, S]) IsDeterministic() bool {
	return s.deterministic
}

// Curve returns the elliptic curve used by this suite.
func (s *Suite[P, B, S]) Curve() Curve[P, B, S] {
	return s.curve
}

// BaseField returns the prime field over which the curve is defined (coordinate field).
func (s *Suite[P, B, S]) BaseField() algebra.PrimeField[B] {
	return s.baseField
}

// ScalarField returns the prime field of scalars (integers modulo the curve order).
func (s *Suite[P, B, S]) ScalarField() algebra.PrimeField[S] {
	return s.scalarField
}

// HashFunc returns the hash function constructor used for message digests.
func (s *Suite[P, B, S]) HashFunc() func() hash.Hash {
	return s.hashFunc
}

// HashID returns the crypto.Hash identifier for deterministic suites, or 0 for randomised suites.
func (s *Suite[P, B, S]) HashID() crypto.Hash {
	return s.hashID
}
