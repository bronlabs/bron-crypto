package elgamal

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/products"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

type PublicKey[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	v E
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

type Plaintext[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	v E
}

func (p *Plaintext[E, S]) Value() E {
	return p.v
}

func (p *Plaintext[E, S]) Wrap(v E) (Plaintext[E, S], error) {
	return Plaintext[E, S]{v}, nil
}

type Ciphertext[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	v *products.DirectProductGroupElement[E, E]
}

func (c *Ciphertext[E, S]) Value() *products.DirectProductGroupElement[E, E] {
	return c.v
}

func (c *Ciphertext[E, S]) Wrap(v *products.DirectProductGroupElement[E, E]) (*Ciphertext[E, S], error) {
	if v == nil {
		return nil, errs.NewIsNil("ciphertext value")
	}
	if v.Left().IsOpIdentity() {
		return nil, errs.NewValue("nonce component is identity")
	}
	return &Ciphertext[E, S]{v}, nil
}

func (c *Ciphertext[E, S]) ScalarOp(m *Plaintext[E, S]) *Ciphertext[E, S] {
	if m == nil {
		return c
	}
	outv := c.v.Clone()
	outv.Set(c.v.Left(), c.v.Right().Op(m.Value()))
	out, err := c.Wrap(outv)
	if err != nil {
		panic(err)
	}
	return out
}

type Nonce[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	v S
}

func (n *Nonce[E, S]) Value() S {
	return n.v
}

func (n *Nonce[E, S]) Wrap(v S) (Nonce[E, S], error) {
	if v.IsZero() {
		return Nonce[E, S]{}, errs.NewValue("nonce is zero")
	}
	return Nonce[E, S]{v}, nil
}

func _[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]]() {
	var _ encryption.PublicKey[*PublicKey[E, S]] = (*PublicKey[E, S])(nil)
	var _ encryption.PrivateKey[*PrivateKey[E, S], *PublicKey[E, S]] = (*PrivateKey[E, S])(nil)
}
