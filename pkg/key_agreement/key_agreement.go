package key_agreement

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
)

// Type represents the type of key agreement algorithm.
type Type string

// NewPrivateKey creates a new PrivateKey instance.
func NewPrivateKey[V algebra.UintLike[V]](v V, t Type) (*PrivateKey[V], error) {
	if v.IsZero() {
		return nil, ErrInvalidKey.WithMessage("private key is zero")
	}

	return &PrivateKey[V]{v: v, t: t}, nil
}

// PrivateKey represents a private key in a key agreement scheme.
type PrivateKey[V algebra.UintLike[V]] struct {
	v V
	t Type
}

// Type returns the type of the private key.
func (sk *PrivateKey[V]) Type() Type {
	return sk.t
}

// Value returns the value of the private key.
func (sk *PrivateKey[V]) Value() V {
	return sk.v
}

// Equal checks if two private keys are equal.
func (sk *PrivateKey[V]) Equal(other *PrivateKey[V]) bool {
	if sk == nil && other == nil {
		return sk == other
	}
	return sk.v.Equal(other.v) && sk.t == other.t
}

// NewPublicKey creates a new PublicKey instance.
func NewPublicKey[V algebra.AbelianGroupElement[V, S], S algebra.UintLike[S]](v V, t Type) (*PublicKey[V, S], error) {
	if v.IsOpIdentity() || !v.IsTorsionFree() {
		return nil, ErrInvalidKey.WithMessage("public key is invalid: zero or not torsion free")
	}

	return &PublicKey[V, S]{v: v, t: t}, nil
}

// PublicKey represents a public key in a key agreement scheme.
type PublicKey[V algebra.AbelianGroupElement[V, S], S algebra.UintLike[S]] struct {
	v V
	t Type
}

// Type returns the type of the public key.
func (pk *PublicKey[V, S]) Type() Type {
	return pk.t
}

// Value returns the value of the public key.
func (pk *PublicKey[V, S]) Value() V {
	return pk.v
}

// Equal checks if two public keys are equal.
func (pk *PublicKey[V, S]) Equal(other *PublicKey[V, S]) bool {
	if pk == nil && other == nil {
		return pk == other
	}
	return pk.v.Equal(other.v) && pk.t == other.t
}

// HashCode returns the hash code of the public key.
func (pk *PublicKey[V, S]) HashCode() base.HashCode {
	return pk.v.HashCode()
}

// Clone creates a deep copy of the public key.
func (pk *PublicKey[V, S]) Clone() *PublicKey[V, S] {
	return &PublicKey[V, S]{v: pk.v.Clone(), t: pk.t}
}

// NewSharedKey creates a new SharedKey instance.
func NewSharedKey(v []byte, t Type) (*SharedKey, error) {
	if ct.SliceIsZero(v) == ct.True {
		return nil, ErrInvalidKey.WithMessage("shared key is zero")
	}
	return &SharedKey{v: v, t: t}, nil
}

// SharedKey represents a shared key derived from a key agreement scheme.
type SharedKey struct {
	v []byte
	t Type
}

// Bytes returns the byte representation of the shared key.
func (k *SharedKey) Bytes() []byte {
	return k.v
}

// Type returns the type of the shared key.
func (k *SharedKey) Type() Type {
	return k.t
}

// Equal checks if two shared keys are equal.
func (k *SharedKey) Equal(other *SharedKey) bool {
	if k == nil && other == nil {
		return k == other
	}
	return ct.SliceEqual(k.v, other.v) == ct.True && k.t == other.t
}

var (
	ErrInvalidKey = errs2.New("invalid key")
)
