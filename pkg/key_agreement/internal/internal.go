package internal

import "github.com/bronlabs/bron-crypto/pkg/base/algebra"

func NewPrivateKey[V any, T ~string](v V, t T) *PrivateKey[V, T] {
	return &PrivateKey[V, T]{v: v, t: t}
}

type PrivateKey[V any, T ~string] struct {
	v V
	t T
}

func (sk *PrivateKey[V, T]) Type() T {
	return sk.t
}

func (sk *PrivateKey[V, T]) Value() V {
	return sk.v
}

func NewPublicKey[V algebra.GroupElement[V], T ~string](v V, t T) *PublicKey[V, T] {
	return &PublicKey[V, T]{v: v, t: t}
}

type PublicKey[V algebra.GroupElement[V], T ~string] struct {
	v V
	t T
}

func (pk *PublicKey[V, T]) Type() T {
	return pk.t
}

func (pk *PublicKey[V, T]) Value() V {
	return pk.v
}

// func NewSharedKey[V interface {
// 	Bytes() []byte
// }, T ~string](v V, t T) *SharedKey[V, T] {
// 	return &SharedKey[V, T]{v: v, t: t}
// }

func NewSharedKey[T ~string](v []byte, t T) *SharedKey[T] {
	return &SharedKey[T]{v: v, t: t}
}

type SharedKey[T ~string] struct {
	v []byte
	t T
}

func (k *SharedKey[T]) Bytes() []byte {
	return k.v
}

func (k *SharedKey[T]) Type() T {
	return k.t
}
