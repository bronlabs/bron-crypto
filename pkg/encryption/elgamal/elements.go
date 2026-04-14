package elgamal

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
)

func NewCiphertextSpace[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]](g UnderlyingGroup[E, S]) (*CiphertextSpace[E, S], error) {
	if g == nil {
		return nil, ErrIsNil.WithMessage("g")
	}
	out, err := constructions.NewFiniteDirectSumModule(g, 2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create ciphertext space")
	}
	return &CiphertextSpace[E, S]{v: out}, nil
}

type CiphertextSpace[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	v *constructions.FiniteDirectSumModule[UnderlyingGroup[E, S], E, S]
}

func (cts *CiphertextSpace[E, S]) Value() *constructions.FiniteDirectSumModule[UnderlyingGroup[E, S], E, S] {
	if cts == nil {
		return nil
	}
	return cts.v
}

func (cts *CiphertextSpace[E, S]) Sample(prng io.Reader) (*Ciphertext[E, S], error) {
	if cts == nil {
		return nil, ErrIsNil.WithMessage("ciphertext space")
	}
	v1, err := algebrautils.RandomNonIdentity(cts.v.Base(), prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to sample random element for ciphertext space")
	}
	v2, err := algebrautils.RandomNonIdentity(cts.v.Base(), prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to sample random element for ciphertext space")
	}
	return cts.New(v1, v2)
}

func (cts *CiphertextSpace[E, S]) New(c1, c2 E) (*Ciphertext[E, S], error) {
	if cts == nil {
		return nil, ErrIsNil.WithMessage("ciphertext space")
	}
	out, err := cts.v.New(c1, c2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new ciphertext element")
	}
	return &Ciphertext[E, S]{v: out}, nil
}

func (cts *CiphertextSpace[E, S]) ScalarRing() algebra.ZModLike[S] {
	if cts == nil {
		return nil
	}
	return algebra.StructureMustBeAs[algebra.ZModLike[S]](cts.v.ScalarStructure())
}

func NewPublicKey[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]](v E) (*PublicKey[E, S], error) {
	if utils.IsNil(v) {
		return nil, ErrIsNil.WithMessage("public key value")
	}
	if !v.IsOpIdentity() {
		return nil, ErrSubGroupMembership.WithMessage("public key value cannot be the identity element")
	}
	if !v.IsTorsionFree() {
		return nil, ErrSubGroupMembership.WithMessage("public key value is not torsion free")
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

func (pk *PublicKey[E, S]) Group() UnderlyingGroup[E, S] {
	if pk == nil {
		return nil
	}
	return algebra.StructureMustBeAs[UnderlyingGroup[E, S]](pk.v.Structure())
}

func (pk *PublicKey[E, S]) HashCode() base.HashCode {
	if pk == nil {
		return 0
	}
	return pk.v.HashCode()
}

func NewPrivateKey[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]](group UnderlyingGroup[E, S], v S) (*PrivateKey[E, S], error) {
	if utils.IsNil(v) {
		return nil, ErrIsNil.WithMessage("private key value")
	}
	if v.IsOpIdentity() {
		return nil, ErrSubGroupMembership.WithMessage("private key value cannot be the identity element")
	}
	if group == nil {
		return nil, ErrIsNil.WithMessage("group")
	}
	pk, err := NewPublicKey(group.Generator().ScalarOp(v))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create public key from private key value")
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
		return nil, ErrIsNil.WithMessage("plaintext value")
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
		return nil, ErrIsNil.WithMessage("ciphertext components")
	}
	g := algebra.StructureMustBeAs[UnderlyingGroup[E, S]](c1.Structure())
	ctSpace, err := NewCiphertextSpace(g)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create ciphertext space")
	}
	out, err := ctSpace.New(c1, c2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new ciphertext element")
	}
	return out, nil
}

type Ciphertext[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	v *constructions.FiniteDirectSumModuleElement[E, S]
}

func (c *Ciphertext[E, S]) CiphertextSpace() *CiphertextSpace[E, S] {
	if c == nil {
		return nil
	}
	directSumModule := algebra.StructureMustBeAs[*constructions.FiniteDirectSumModule[UnderlyingGroup[E, S], E, S]](c.v.Structure())
	return &CiphertextSpace[E, S]{v: directSumModule}
}

func (c *Ciphertext[E, S]) ScalarRing() algebra.ZModLike[S] {
	if c == nil {
		return nil
	}
	return c.CiphertextSpace().ScalarRing()
}

func (c *Ciphertext[E, S]) Value() *constructions.FiniteDirectSumModuleElement[E, S] {
	return c.v
}

func (c *Ciphertext[E, S]) Shift(_ *PublicKey[E, S], message *Plaintext[E, S]) (*Ciphertext[E, S], error) {
	if c == nil {
		return nil, ErrIsNil.WithMessage("ciphertext")
	}
	if message == nil {
		return nil, ErrIsNil.WithMessage("message")
	}
	ctSpace := c.CiphertextSpace()
	c1 := c.v.Components()[0]
	c2 := c.v.Components()[1].Op(message.v)
	out, err := ctSpace.New(c1, c2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new ciphertext element")
	}
	return out, nil
}

func (c *Ciphertext[E, S]) ReRandomiseWithNonce(publicKey *PublicKey[E, S], nonce *Nonce[S]) (*Ciphertext[E, S], error) {
	if c == nil {
		return nil, ErrIsNil.WithMessage("ciphertext")
	}
	if publicKey == nil {
		return nil, ErrIsNil.WithMessage("public key")
	}
	if nonce == nil {
		return nil, ErrIsNil.WithMessage("nonce")
	}
	gr := c.CiphertextSpace().Value().Base().Generator().ScalarOp(nonce.Value())
	hr := publicKey.Value().ScalarOp(nonce.Value())
	return NewCiphertext(gr, hr)
}

func (c *Ciphertext[E, S]) ReRandomise(publicKey *PublicKey[E, S], prng io.Reader) (*Ciphertext[E, S], *Nonce[S], error) {
	if c == nil {
		return nil, nil, ErrIsNil.WithMessage("ciphertext")
	}
	nonceValue, err := algebrautils.RandomNonIdentity(c.ScalarRing(), prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to generate nonce value")
	}
	nonce, err := NewNonce(nonceValue)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to create nonce")
	}
	ciphertext, err := c.ReRandomiseWithNonce(publicKey, nonce)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to re-randomise ciphertext")
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

func (c *Ciphertext[E, S]) ScalarOp(scalar algebra.Numeric) *Ciphertext[E, S] {
	if c == nil {
		return nil
	}
	if scalar == nil {
		return c
	}
	return &Ciphertext[E, S]{v: algebrautils.ScalarMul(c.v, scalar)}
}

func NewNonce[S algebra.UintLike[S]](v S) (*Nonce[S], error) {
	if utils.IsNil(v) {
		return nil, ErrIsNil.WithMessage("nonce value")
	}
	if v.IsOpIdentity() {
		return nil, ErrValue.WithMessage("nonce value cannot be the identity element")
	}
	return &Nonce[S]{v: v}, nil
}

type Nonce[S algebra.UintLike[S]] struct {
	v S
}

func (n *Nonce[S]) Value() S {
	return n.v
}

func (n *Nonce[S]) Op(other *Nonce[S]) *Nonce[S] {
	if n == nil || other == nil {
		return nil
	}
	return &Nonce[S]{v: n.v.Op(other.v)}
}

func (n *Nonce[S]) Equal(x *Nonce[S]) bool {
	if n == nil || x == nil {
		return n == x
	}
	return n.v.Equal(x.v)
}
