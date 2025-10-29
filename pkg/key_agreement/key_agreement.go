package key_agreement

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type Type string

func NewPrivateKey[V algebra.UintLike[V]](v V, t Type) (*PrivateKey[V], error) {
	if v.IsZero() {
		return nil, errs.NewIsZero("invalid private key")
	}

	return &PrivateKey[V]{v: v, t: t}, nil
}

type PrivateKey[V algebra.UintLike[V]] struct {
	v V
	t Type
}

func (sk *PrivateKey[V]) Type() Type {
	return sk.t
}

func (sk *PrivateKey[V]) Value() V {
	return sk.v
}

func (sk *PrivateKey[V]) Equal(other *PrivateKey[V]) bool {
	if sk == nil && other == nil {
		return sk == other
	}
	return sk.v.Equal(other.v) && sk.t == other.t
}

func NewPublicKey[V algebra.AbelianGroupElement[V, S], S algebra.UintLike[S]](v V, t Type) (*PublicKey[V, S], error) {
	if v.IsOpIdentity() || !v.IsTorsionFree() {
		return nil, errs.NewIsIdentity("invalid public key")
	}

	return &PublicKey[V, S]{v: v, t: t}, nil
}

type PublicKey[V algebra.AbelianGroupElement[V, S], S algebra.UintLike[S]] struct {
	v V
	t Type
}

func (pk *PublicKey[V, S]) Type() Type {
	return pk.t
}

func (pk *PublicKey[V, S]) Value() V {
	return pk.v
}

func (pk *PublicKey[V, S]) Equal(other *PublicKey[V, S]) bool {
	if pk == nil && other == nil {
		return pk == other
	}
	return pk.v.Equal(other.v) && pk.t == other.t
}

func NewSharedKey(v []byte, t Type) (*SharedKey, error) {
	if ct.SliceIsZero(v) == ct.True {
		return nil, errs.NewIsZero("invalid shared key")
	}
	return &SharedKey{v: v, t: t}, nil
}

type SharedKey struct {
	v []byte
	t Type
}

func (k *SharedKey) Bytes() []byte {
	return k.v
}

func (k *SharedKey) Type() Type {
	return k.t
}

func (k *SharedKey) Equal(other *SharedKey) bool {
	if k == nil && other == nil {
		return k == other
	}
	return ct.SliceEqual(k.v, other.v) == ct.True && k.t == other.t
}
