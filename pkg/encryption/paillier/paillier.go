package paillier

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

const Name encryption.Name = "Paillier"

type EncryptionKey[EK encryption.GroupHomomorphicEncryptionKey[
	EK,
	*Plaintext, *num.ZMod, *num.Uint,
	*Nonce, *znstar.RSAGroupUnknownOrder, *znstar.RSAGroupElementUnknownOrder,
	*Ciphertext, *znstar.PaillierGroupUnknownOrder, *znstar.PaillierGroupElementUnknownOrder,
	*num.Int,
],
] = encryption.GroupHomomorphicEncryptionKey[
	EK,
	*Plaintext, *num.ZMod, *num.Uint,
	*Nonce, *znstar.RSAGroupUnknownOrder, *znstar.RSAGroupElementUnknownOrder,
	*Ciphertext, *znstar.PaillierGroupUnknownOrder, *znstar.PaillierGroupElementUnknownOrder,
	*num.Int,
]

func NewCiphertext[A znstar.ArithmeticPaillier](group *znstar.PaillierGroup[A], v *num.NatPlus) (*Ciphertext, error) {
	if group == nil || v == nil {
		return nil, encryption.ErrIsNil.WithMessage("group and value must not be nil")
	}
	c, err := group.FromNatPlus(v)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create ciphertext from value")
	}
	return &Ciphertext{c: c.ForgetOrder()}, nil
}

func NewCiphertextFromGroupElement[A znstar.ArithmeticPaillier](v *znstar.PaillierGroupElement[A]) (*Ciphertext, error) {
	if v == nil {
		return nil, encryption.ErrIsNil.WithMessage("group element must not be nil")
	}
	return &Ciphertext{c: v.ForgetOrder()}, nil
}

type Ciphertext struct {
	c *znstar.PaillierGroupElementUnknownOrder
}

type ciphertextDTO struct {
	C *znstar.PaillierGroupElementUnknownOrder `cbor:"c"`
}

func (c *Ciphertext) Value() *znstar.PaillierGroupElementUnknownOrder {
	return c.c
}

func (c *Ciphertext) Group() *znstar.PaillierGroupUnknownOrder {
	return c.c.Group()
}

func (c *Ciphertext) Equal(other *Ciphertext) bool {
	if c == nil || other == nil {
		return c == other
	}
	return c.c.Equal(other.c)
}

func (c *Ciphertext) HashCode() base.HashCode {
	return c.c.HashCode()
}

func (c *Ciphertext) Bytes() []byte {
	return c.c.Bytes()
}

func (c *Ciphertext) MarshalCBOR() ([]byte, error) {
	dto := &ciphertextDTO{
		C: c.c,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal ciphertext")
	}
	return out, nil
}

func (c *Ciphertext) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*ciphertextDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal ciphertext")
	}
	if dto.C == nil {
		return encryption.ErrIsNil.WithMessage("ciphertext component C is nil")
	}
	c.c = dto.C
	return nil
}

func NewNonce[A znstar.ArithmeticPaillier](group *znstar.PaillierGroup[A], input *num.NatPlus) (*Nonce, error) {
	if group == nil || input == nil {
		return nil, encryption.ErrIsNil.WithMessage("group and value must not be nil")
	}
	nonceGroup, err := znstar.NewRSAGroupOfUnknownOrder(group.N())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create nonce group")
	}
	r, err := nonceGroup.FromNatPlus(input)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create nonce from value")
	}
	return &Nonce{r: r.ForgetOrder()}, nil
}

func NewNonceFromGroupElement[A znstar.ArithmeticRSA](v *znstar.RSAGroupElement[A]) (*Nonce, error) {
	if v == nil {
		return nil, encryption.ErrIsNil.WithMessage("group element must not be nil")
	}
	return &Nonce{r: v.ForgetOrder()}, nil
}

type Nonce struct {
	r *znstar.RSAGroupElementUnknownOrder
}

type nonceDTO struct {
	R *znstar.RSAGroupElementUnknownOrder `cbor:"r"`
}

func (n *Nonce) Value() *znstar.RSAGroupElementUnknownOrder {
	return n.r
}

func (n *Nonce) Group() *znstar.RSAGroupUnknownOrder {
	return n.r.Group()
}

func (n *Nonce) Equal(other *Nonce) bool {
	if n == nil || other == nil {
		return n == other
	}
	return n.r.Equal(other.r)
}

func (n *Nonce) HashCode() base.HashCode {
	return n.r.HashCode()
}

func (n *Nonce) Bytes() []byte {
	return n.r.Bytes()
}

func (n *Nonce) MarshalCBOR() ([]byte, error) {
	dto := &nonceDTO{
		R: n.r,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal nonce")
	}
	return out, nil
}

func (n *Nonce) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*nonceDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal nonce")
	}
	if dto.R == nil {
		return encryption.ErrIsNil.WithMessage("nonce component R is nil")
	}
	n.r = dto.R
	return nil
}

func NewPlaintext(p *num.Uint) (*Plaintext, error) {
	if p == nil {
		return nil, encryption.ErrIsNil.WithMessage("value must not be nil")
	}
	return &Plaintext{
		p: p,
	}, nil
}

func NewPlaintextFromNat(p *num.Nat, modulus *num.NatPlus) (*Plaintext, error) {
	if p == nil || modulus == nil {
		return nil, encryption.ErrIsNil.WithMessage("plaintext and modulus must not be nil")
	}
	if !p.Compare(modulus.Nat()).IsLessThan() {
		return nil, encryption.ErrOutOfRange.WithMessage("plaintext value must be in range [0, modulus)")
	}
	zMod, err := num.NewZMod(modulus)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create ZMod for modulus")
	}
	pModN, err := zMod.FromNat(p)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not reduce plaintext modulo modulus")
	}
	return &Plaintext{
		p: pModN,
	}, nil
}

func NewPlaintextSymmetric(p *num.Int, modulus *num.NatPlus) (*Plaintext, error) {
	if p == nil || modulus == nil {
		return nil, encryption.ErrIsNil.WithMessage("plaintext and modulus must not be nil")
	}
	if !p.IsInRangeSymmetric(modulus) {
		return nil, encryption.ErrOutOfRange.WithMessage("plaintext value must be in range [-modulus/2, modulus/2)")
	}
	zMod, err := num.NewZMod(modulus)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create ZMod for modulus")
	}
	pModN, err := zMod.FromInt(p)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not reduce plaintext modulo modulus")
	}
	return &Plaintext{
		p: pModN,
	}, nil
}

type Plaintext struct {
	p *num.Uint
}

type plaintextDTO struct {
	P *num.Uint `cbor:"p"`
}

func (pt *Plaintext) Normalise() *num.Int {
	out, err := num.Z().FromUintSymmetric(pt.p)
	if err != nil {
		panic(err)
	}
	return out
}

func (pt *Plaintext) Value() *num.Uint {
	return pt.p
}

func (pt *Plaintext) Modulus() *num.NatPlus {
	return pt.p.Modulus()
}

func (pt *Plaintext) Group() *num.ZMod {
	return pt.p.Group()
}

func (pt *Plaintext) Equal(other *Plaintext) bool {
	if pt == nil || other == nil {
		return pt == other
	}
	return pt.p.Equal(other.p)
}

func (pt *Plaintext) HashCode() base.HashCode {
	return pt.p.HashCode()
}

func (pt *Plaintext) Bytes() []byte {
	return pt.p.Bytes()
}

func (pt *Plaintext) MarshalCBOR() ([]byte, error) {
	dto := &plaintextDTO{
		P: pt.p,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal plaintext")
	}
	return out, nil
}

func (pt *Plaintext) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*plaintextDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal plaintext")
	}
	ptt, err := NewPlaintext(dto.P)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid plaintext value or modulus")
	}
	*pt = *ptt
	return nil
}
