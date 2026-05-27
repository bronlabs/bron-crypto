package paillier

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

// Name identifies the Paillier encryption scheme.
const Name encryption.Name = "Paillier"

// EncryptionKey is the group-homomorphic encryption-key interface specialised to
// Paillier's plaintext (Z_N), nonce (Z*_N), and ciphertext (Z*_{N²}) types. Both
// PublicKey and SecretKey satisfy it; use it as a constraint when writing code
// generic over either.
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

// NewCiphertext wraps a value as a ciphertext, validating that it is a member of
// the Paillier group Z*_{N²} via the group's constructor. It does not check that
// the value is a well-formed encryption of any particular plaintext.
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

// NewCiphertextFromGroupElement wraps an existing Z*_{N²} group element as a
// ciphertext. It is the constructor used by the homomorphic ciphertext operations.
func NewCiphertextFromGroupElement[A znstar.ArithmeticPaillier](v *znstar.PaillierGroupElement[A]) (*Ciphertext, error) {
	if v == nil {
		return nil, encryption.ErrIsNil.WithMessage("group element must not be nil")
	}
	return &Ciphertext{c: v.ForgetOrder()}, nil
}

// Ciphertext is a Paillier ciphertext (1+N)^m · r^N mod N², an element of Z*_{N²}.
// It is public: under the Decisional Composite Residuosity assumption it
// computationally hides m while the nonce r remains secret.
type Ciphertext struct {
	c *znstar.PaillierGroupElementUnknownOrder
}

type ciphertextDTO struct {
	C *znstar.PaillierGroupElementUnknownOrder `cbor:"c"`
}

// Value returns the underlying Z*_{N²} group element.
func (c *Ciphertext) Value() *znstar.PaillierGroupElementUnknownOrder {
	return c.c
}

// Group returns the Paillier group Z*_{N²} in which the ciphertext lives.
func (c *Ciphertext) Group() *znstar.PaillierGroupUnknownOrder {
	return c.c.Group()
}

// Equal reports whether two ciphertexts are the same group element, treating nil as
// equal only to nil. Ciphertexts are public, so this need not be constant time.
func (c *Ciphertext) Equal(other *Ciphertext) bool {
	if c == nil || other == nil {
		return c == other
	}
	return c.c.Equal(other.c)
}

// HashCode returns a non-cryptographic hash of the ciphertext for use as a map key.
func (c *Ciphertext) HashCode() base.HashCode {
	return c.c.HashCode()
}

// Bytes returns the big-endian byte encoding of the ciphertext element.
func (c *Ciphertext) Bytes() []byte {
	return c.c.Bytes()
}

// MarshalCBOR encodes the ciphertext group element.
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

// UnmarshalCBOR decodes a ciphertext, rejecting a nil component. This is a
// deserialization trust boundary: membership of the element in Z*_{N²} is enforced
// by the group-element decoder, not re-checked here.
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

// NewNonce wraps a value as an encryption nonce, validating that it is a unit in
// Z*_N (the RSA group built from the Paillier modulus N).
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

// NewNonceFromGroupElement wraps an existing Z*_N group element as a nonce. It is
// the constructor used by the homomorphic nonce operations.
func NewNonceFromGroupElement[A znstar.ArithmeticRSA](v *znstar.RSAGroupElement[A]) (*Nonce, error) {
	if v == nil {
		return nil, encryption.ErrIsNil.WithMessage("group element must not be nil")
	}
	return &Nonce{r: v.ForgetOrder()}, nil
}

// Nonce is the encryption randomness r ∈ Z*_N; it enters the ciphertext as the
// N-th power r^N mod N². It is secret — revealing or reusing it before opening lets
// a holder strip the randomness and recover the plaintext, breaking hiding.
type Nonce struct {
	r *znstar.RSAGroupElementUnknownOrder
}

type nonceDTO struct {
	R *znstar.RSAGroupElementUnknownOrder `cbor:"r"`
}

// Value returns the underlying Z*_N group element. The result is secret.
func (n *Nonce) Value() *znstar.RSAGroupElementUnknownOrder {
	return n.r
}

// Group returns the nonce group Z*_N.
func (n *Nonce) Group() *znstar.RSAGroupUnknownOrder {
	return n.r.Group()
}

// Equal reports whether two nonces are the same group element, treating nil as
// equal only to nil.
func (n *Nonce) Equal(other *Nonce) bool {
	if n == nil || other == nil {
		return n == other
	}
	return n.r.Equal(other.r)
}

// HashCode returns a non-cryptographic hash of the nonce for use as a map key.
func (n *Nonce) HashCode() base.HashCode {
	return n.r.HashCode()
}

// Bytes returns the big-endian byte encoding of the nonce. The result is secret.
func (n *Nonce) Bytes() []byte {
	return n.r.Bytes()
}

// MarshalCBOR encodes the nonce group element. The output is secret material.
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

// UnmarshalCBOR decodes a nonce, rejecting a nil component. This is a
// deserialization trust boundary for secret material; membership in Z*_N is
// enforced by the group-element decoder.
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

// NewPlaintext wraps a residue in Z_N as a plaintext, rejecting nil. The modulus N
// is carried by the supplied Uint.
func NewPlaintext(p *num.Uint) (*Plaintext, error) {
	if p == nil {
		return nil, encryption.ErrIsNil.WithMessage("value must not be nil")
	}
	return &Plaintext{
		p: p,
	}, nil
}

// NewPlaintextFromNat reduces a natural number into Z_N as a plaintext, rejecting a
// value outside [0, modulus).
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

// NewPlaintextSymmetric reduces a signed integer in the symmetric range
// [−modulus/2, modulus/2) into Z_N as a plaintext. It is convenient for committing
// to signed values whose magnitude is bounded.
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

// Plaintext is the message m, a residue in Z_N (integers modulo the Paillier
// modulus N). Paillier's homomorphism adds plaintexts modulo N.
type Plaintext struct {
	p *num.Uint
}

type plaintextDTO struct {
	P *num.Uint `cbor:"p"`
}

// Normalise returns m as a signed integer in the symmetric range (−N/2, N/2], the
// canonical signed representative of the residue.
func (pt *Plaintext) Normalise() *num.Int {
	out, err := num.Z().FromUintSymmetric(pt.p)
	if err != nil {
		panic(err)
	}
	return out
}

// Value returns the residue m as an element of Z_N.
func (pt *Plaintext) Value() *num.Uint {
	return pt.p
}

// Modulus returns the plaintext modulus N.
func (pt *Plaintext) Modulus() *num.NatPlus {
	return pt.p.Modulus()
}

// Group returns the plaintext ring Z_N.
func (pt *Plaintext) Group() *num.ZMod {
	return pt.p.Group()
}

// Equal reports whether two plaintexts are the same residue, treating nil as equal
// only to nil.
func (pt *Plaintext) Equal(other *Plaintext) bool {
	if pt == nil || other == nil {
		return pt == other
	}
	return pt.p.Equal(other.p)
}

// HashCode returns a non-cryptographic hash of the plaintext for use as a map key.
func (pt *Plaintext) HashCode() base.HashCode {
	return pt.p.HashCode()
}

// Bytes returns the big-endian byte encoding of the plaintext residue.
func (pt *Plaintext) Bytes() []byte {
	return pt.p.Bytes()
}

// MarshalCBOR encodes the plaintext residue.
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

// UnmarshalCBOR decodes a plaintext residue, rejecting nil via NewPlaintext.
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
