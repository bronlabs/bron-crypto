package ecdsa

import (
	nativeEcdsa "crypto/ecdsa"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/errs-go/pkg/errs"
)

// PrivateKey represents an ECDSA private key as a scalar value d in [1, n-1],
// where n is the order of the curve's base point. The corresponding public key
// Q = d * G is stored alongside for efficient access.
//
// Security: Private keys must be generated using a cryptographically secure
// random source and protected against disclosure.
type PrivateKey[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	sk S
	pk *PublicKey[P, B, S]
}

// NewPrivateKey creates a PrivateKey from a scalar value and its corresponding public key.
// The constructor validates that sk * G equals the provided public key to ensure consistency.
func NewPrivateKey[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](sk S, pk *PublicKey[P, B, S]) (*PrivateKey[P, B, S], error) {
	if pk == nil {
		return nil, ErrInvalidArgument.WithMessage("public key is nil")
	}
	if sk.IsZero() {
		return nil, ErrFailed.WithMessage("secret key is zero")
	}
	curve, err := algebra.StructureAs[Curve[P, B, S]](pk.Value().Structure())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("curve structure is not supported")
	}
	if !curve.ScalarBaseMul(sk).Equal(pk.Value()) {
		return nil, ErrFailed.WithMessage("private key doesn't match public key")
	}

	key := &PrivateKey[P, B, S]{
		sk: sk,
		pk: pk,
	}
	return key, nil
}

// Value returns the underlying scalar value of the private key.
func (sk *PrivateKey[P, B, S]) Value() S {
	return sk.sk
}

// PublicKey returns the public key corresponding to this private key.
func (sk *PrivateKey[P, B, S]) PublicKey() *PublicKey[P, B, S] {
	return sk.pk
}

// Equal returns true if both private keys have the same scalar value.
func (sk *PrivateKey[P, B, S]) Equal(rhs *PrivateKey[P, B, S]) bool {
	if sk == nil || rhs == nil {
		return sk == rhs
	}
	return sk.sk.Equal(rhs.sk)
}

// Clone returns a deep copy of the private key.
func (sk *PrivateKey[P, B, S]) Clone() *PrivateKey[P, B, S] {
	if sk == nil {
		return nil
	}

	clone := &PrivateKey[P, B, S]{
		sk: sk.sk.Clone(),
		pk: sk.pk.Clone(),
	}
	return clone
}

// ToElliptic converts the private key to Go's standard library ecdsa.PrivateKey format.
// This enables interoperability with Go's crypto/ecdsa package.
func (sk *PrivateKey[P, B, S]) ToElliptic() *nativeEcdsa.PrivateKey {
	nativeSk := &nativeEcdsa.PrivateKey{
		PublicKey: *sk.pk.ToElliptic(),
		D:         sk.sk.Cardinal().Big(),
	}

	return nativeSk
}
