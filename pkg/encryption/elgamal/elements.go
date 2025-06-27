package elgamal

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

func NewPublicKey[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]](v E) (*PublicKey[E, S], error) {
	if utils.IsNil(v) {
		return nil, errs.NewIsNil("public key value")
	}
	if !v.IsOpIdentity() {
		return nil, errs.NewIsIdentity("public key value cannot be the identity element")
	}
	if !v.IsTorsionFree() {
		return nil, errs.NewType("public key value is not torsion free")
	}
	return &PublicKey[E, S]{v: v}, nil
}

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

func (pk *PublicKey[E, S]) HashCode() base.HashCode {
	if pk == nil {
		return 0
	}
	return pk.v.HashCode()
}

func NewPrivateKey[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]](group UnderlyingGroup[E, S], v S) (*PrivateKey[E, S], error) {
	if utils.IsNil(v) {
		return nil, errs.NewIsNil("private key value")
	}
	if v.IsOpIdentity() {
		return nil, errs.NewIsIdentity("private key value cannot be the identity element")
	}
	if group == nil {
		return nil, errs.NewIsNil("group")
	}
	pk, err := NewPublicKey(group.Generator().ScalarOp(v))
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create public key from private key value")
	}
	return &PrivateKey[E, S]{v: v, pk: *pk}, nil
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

func NewPlaintext[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]](v E) (*Plaintext[E, S], error) {
	if utils.IsNil(v) {
		return nil, errs.NewIsNil("plaintext value")
	}
	return &Plaintext[E, S]{v: v}, nil
}

type Plaintext[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	v E
}

func (p *Plaintext[E, S]) Value() E {
	return p.v
}

func (p *Plaintext[E, S]) Equal(x *Plaintext[E, S]) bool {
	if p == nil || x == nil {
		return p == x
	}
	return p.v.Equal(x.v)
}

func (p *Plaintext[E, S]) Op(other *Plaintext[E, S]) *Plaintext[E, S] {
	if p == nil || other == nil {
		return nil
	}
	return &Plaintext[E, S]{p.v.Op(other.v)}
}

func NewCiphertext[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]](c1, c2 E) (*Ciphertext[E, S], error) {
	if utils.IsNil(c1) || utils.IsNil(c2) {
		return nil, errs.NewIsNil("ciphertext components")
	}
	module, ok := c1.Structure().(UnderlyingGroup[E, S])
	if !ok {
		return nil, errs.NewType("ciphertext value is not a FiniteDirectSumModuleElement")
	}
	ctSpace, err := constructions.NewFiniteDirectSumModule(module, 2)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create ciphertext space")
	}
	out, err := ctSpace.New(c1, c2)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create new ciphertext element")
	}
	return &Ciphertext[E, S]{v: out}, nil
}

type Ciphertext[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	v *constructions.FiniteDirectSumModuleElement[E, S]
}

func (c *Ciphertext[E, S]) CiphertextSpace() *constructions.FiniteDirectSumModule[UnderlyingGroup[E, S], E, S] {
	if c == nil {
		return nil
	}
	module, ok := c.v.Structure().(*constructions.FiniteDirectSumModule[UnderlyingGroup[E, S], E, S])
	if !ok {
		panic(errs.NewType("Ciphertext space is not a FiniteDirectSumModule"))
	}
	return module
}

func (c *Ciphertext[E, S]) ScalarField() algebra.ZnLike[S] {
	if c == nil {
		return nil
	}
	module, ok := c.v.Structure().(*constructions.FiniteDirectSumModule[UnderlyingGroup[E, S], E, S])
	if !ok {
		panic(errs.NewType("Ciphertext space is not a FiniteDirectSumModule"))
	}
	sf, ok := module.ScalarStructure().(algebra.ZnLike[S])
	if !ok {
		panic(errs.NewType("Ciphertext space scalar structure is not a ZnLike"))
	}
	return sf
}

func (c *Ciphertext[E, S]) Value() *constructions.FiniteDirectSumModuleElement[E, S] {
	return c.v
}

func (c *Ciphertext[E, S]) ReRandomiseWithNonce(publicKey *PublicKey[E, S], nonce *Nonce[E, S]) (*Ciphertext[E, S], error) {
	if c == nil {
		return nil, errs.NewIsNil("ciphertext")
	}
	if publicKey == nil {
		return nil, errs.NewIsNil("public key")
	}
	if nonce == nil {
		return nil, errs.NewIsNil("nonce")
	}
	gr := c.CiphertextSpace().Base().Generator().ScalarOp(nonce.Value())
	hr := publicKey.Value().ScalarOp(nonce.Value())
	return NewCiphertext(gr, hr)
}

func (c *Ciphertext[E, S]) ReRandomise(publicKey *PublicKey[E, S], prng io.Reader) (*Ciphertext[E, S], *Nonce[E, S], error) {
	if c == nil {
		return nil, nil, errs.NewIsNil("ciphertext")
	}
	if publicKey == nil {
		return nil, nil, errs.NewIsNil("public key")
	}
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng")
	}
	nonceValue, err := algebrautils.RandomNonIdentity(c.ScalarField(), prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "failed to generate nonce value")
	}
	nonce := &Nonce[E, S]{v: nonceValue}
	ciphertext, err := c.ReRandomiseWithNonce(publicKey, nonce)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to re-randomise ciphertext")
	}
	return ciphertext, nonce, nil
}

func (c *Ciphertext[E, S]) Equal(x *Ciphertext[E, S]) bool {
	if c == nil || x == nil {
		return c == x
	}
	return c.v.Equal(x.v)
}

func (c *Ciphertext[E, S]) Op(other *Ciphertext[E, S]) *Ciphertext[E, S] {
	if c == nil {
		return nil
	}
	if other == nil {
		return c
	}
	return &Ciphertext[E, S]{v: c.v.Op(other.v)}
}

func NewNonce[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]](v S) (*Nonce[E, S], error) {
	if utils.IsNil(v) {
		return nil, errs.NewIsNil("nonce value")
	}
	if v.IsOpIdentity() {
		return nil, errs.NewIsIdentity("nonce value cannot be the identity element")
	}
	return &Nonce[E, S]{v: v}, nil
}

type Nonce[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	v S
}

func (n *Nonce[E, S]) Value() S {
	return n.v
}

func _[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]]() {
	var (
		_ encryption.PrivateKey[*PrivateKey[E, S]]                                               = (*PrivateKey[E, S])(nil)
		_ encryption.PublicKey[*PublicKey[E, S]]                                                 = (*PublicKey[E, S])(nil)
		_ encryption.ReRandomisableCiphertext[*Ciphertext[E, S], *Nonce[E, S], *PublicKey[E, S]] = (*Ciphertext[E, S])(nil)
	)
}
