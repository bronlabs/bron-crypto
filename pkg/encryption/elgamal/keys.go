package elgamal

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/groups"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

func PublicKeySpace[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]]() groups.Group[E] {

	return nil
}

type PublicKey[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	v E
}

func (pk *PublicKey[E, S]) Scheme() types.Scheme[encryption.Type] {
	return nil
}

func (pk *PublicKey[E, S]) Value() E {
	return pk.v
}

func (pk *PublicKey[E, S]) Equal(x *PublicKey[E, S]) bool {
	return pk.v.Equal(x.v)
}

func (pk *PublicKey[E, S]) Clone() *PublicKey[E, S] {
	out := &PublicKey[E, S]{}
	out.v = pk.v.Clone()
	return out
}

func (pk *PublicKey[E, S]) MarshalBinary() ([]byte, error) {
	panic("implement me")
}

func (pk *PublicKey[E, S]) UnmarshalBinary(input []byte) error {
	panic("implement me")
}

type PrivateKey[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	v  S
	pk PublicKey[E, S]
}

func (sk *PrivateKey[E, S]) Value() S {
	return sk.v
}

func (sk *PrivateKey[E, S]) Scheme() types.Scheme[encryption.Type] {
	return nil
}

func (sk *PrivateKey[E, S]) Public() *PublicKey[E, S] {
	return &sk.pk
}

func (sk *PrivateKey[E, S]) Equal(x *PrivateKey[E, S]) bool {
	return sk.v.Equal(x.v) && sk.pk.Equal(&x.pk)
}

func (sk *PrivateKey[E, S]) Clone() *PrivateKey[E, S] {
	out := &PrivateKey[E, S]{}
	out.v = sk.v.Clone()
	out.pk = *sk.pk.Clone()
	return out
}

func (sk *PrivateKey[E, S]) MarshalBinary() ([]byte, error) {
	panic("implement me")
}

func (sk *PrivateKey[E, S]) UnmarshalBinary(input []byte) error {
	panic("implement me")
}

func _[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]]() {
	var _ encryption.PublicKey[*PublicKey[E, S]] = (*PublicKey[E, S])(nil)
	var _ encryption.PrivateKey[*PrivateKey[E, S], *PublicKey[E, S]] = (*PrivateKey[E, S])(nil)
}
