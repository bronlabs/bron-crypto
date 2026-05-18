package paillier

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/internal/gift"
	"github.com/bronlabs/errs-go/errs"
)

func NewPublicKey(group *znstar.PaillierGroupUnknownOrder) (*PublicKey, error) {
	if group == nil {
		return nil, encryption.ErrIsNil.WithMessage("group must not be nil")
	}
	return &PublicKey{group: group}, nil
}

type PublicKey struct {
	group *znstar.PaillierGroupUnknownOrder
}

type publicKeyDTO struct {
	Group *znstar.PaillierGroupUnknownOrder `cbor:"group"`
}

func (pk *PublicKey) Type() encryption.Name {
	return Name
}

func (pk *PublicKey) SampleNonce(prng io.Reader) (*Nonce, error) {
	if prng == nil {
		return nil, encryption.ErrIsNil.WithMessage("prng must not be nil")
	}
	out, err := pk.NonceGroup().Random(prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample nonce")
	}
	return &Nonce{r: out}, nil
}

func (pk *PublicKey) EncryptWithNonce(p *Plaintext, n *Nonce) (*Ciphertext, error) {
	if p == nil || n == nil {
		return nil, encryption.ErrIsNil.WithMessage("plaintext and nonce must not be nil")
	}
	out, err := gift.Encrypt(pk, p, n)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not encrypt message with nonce")
	}
	return out, nil
}

func (pk *PublicKey) Representative(p *Plaintext) (*Ciphertext, error) {
	if p == nil {
		return nil, encryption.ErrIsNil.WithMessage("plaintext must not be nil")
	}
	gm, err := pk.group.Representative(p.Value())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute representative")
	}
	return &Ciphertext{c: gm}, nil
}

func (pk *PublicKey) IdentityNoise(n *Nonce) (*Ciphertext, error) {
	if n == nil {
		return nil, encryption.ErrIsNil.WithMessage("nonce must not be nil")
	}
	embeddedNonce, err := pk.group.EmbedRSA(n.Value())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not embed nonce into group")
	}
	rn, err := pk.group.NthResidue(embeddedNonce)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute nth residue of embedded nonce")
	}
	return &Ciphertext{c: rn}, nil
}

func (pk *PublicKey) NonceOp(first, second *Nonce, rest ...*Nonce) (*Nonce, error) {
	out, err := algebrautils.Op(NewNonceFromGroupElement, first, second, rest...,
	)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to combine nonces")
	}
	return out, nil
}

func (pk *PublicKey) NonceOpInv(n *Nonce) (*Nonce, error) {
	if n == nil {
		return nil, encryption.ErrIsNil.WithMessage("nonce must not be nil")
	}
	return &Nonce{r: n.Value().OpInv()}, nil
}

func (pk *PublicKey) NonceScalarOp(n *Nonce, scalar *num.Int) (*Nonce, error) {
	if n == nil || scalar == nil {
		return nil, encryption.ErrIsNil.WithMessage("nonce and scalar must not be nil")
	}
	return &Nonce{r: n.Value().ScalarOp(scalar)}, nil
}

func (pk *PublicKey) PlaintextOp(first, second *Plaintext, rest ...*Plaintext) (*Plaintext, error) {
	out, err := algebrautils.Op(NewPlaintext, first, second, rest...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to combine plaintexts")
	}
	return out, nil
}

func (pk *PublicKey) PlaintextOpInv(p *Plaintext) (*Plaintext, error) {
	if p == nil {
		return nil, encryption.ErrIsNil.WithMessage("plaintext must not be nil")
	}
	out, err := NewPlaintext(p.Value().OpInv())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new plaintext from inverse value")
	}
	return out, nil
}

func (pk *PublicKey) PlaintextScalarOp(p *Plaintext, scalar *num.Int) (*Plaintext, error) {
	if p == nil || scalar == nil {
		return nil, encryption.ErrIsNil.WithMessage("plaintext and scalar must not be nil")
	}
	v, err := pk.PlaintextGroup().FromInt(p.Value().Lift().Mul(scalar))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new plaintext from scalar multiplied value")
	}
	return &Plaintext{p: v}, nil
}

func (pk *PublicKey) CiphertextOp(c1, c2 *Ciphertext, rest ...*Ciphertext) (*Ciphertext, error) {
	out, err := algebrautils.Op(NewCiphertextFromGroupElement, c1, c2, rest...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute ciphertext operation")
	}
	return out, nil
}

func (pk *PublicKey) CiphertextOpInv(c *Ciphertext) (*Ciphertext, error) {
	if c == nil {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext must not be nil")
	}
	return &Ciphertext{c: c.Value().OpInv()}, nil
}

func (pk *PublicKey) CiphertextScalarOp(c *Ciphertext, scalar *num.Int) (*Ciphertext, error) {
	if c == nil || scalar == nil {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext and scalar must not be nil")
	}
	return &Ciphertext{c: c.Value().ScalarOp(scalar)}, nil
}

func (pk *PublicKey) ReRandomise(c *Ciphertext, nonce *Nonce) (*Ciphertext, error) {
	if c == nil || nonce == nil {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext and nonce must not be nil")
	}
	out, err := gift.ReRandomise(pk, c, nonce)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not re-randomise ciphertext with nonce")
	}
	return &Ciphertext{c: out.Value()}, nil
}

func (pk *PublicKey) Shift(c *Ciphertext, delta *Plaintext) (*Ciphertext, error) {
	if c == nil || delta == nil {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext and delta must not be nil")
	}
	out, err := gift.Shift(pk, c, delta)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not shift ciphertext by delta")
	}
	return &Ciphertext{c: out.Value()}, nil
}

func (pk *PublicKey) Group() *znstar.PaillierGroupUnknownOrder {
	return pk.group
}

func (pk *PublicKey) PlaintextGroup() *num.ZMod {
	return pk.NonceGroup().AmbientGroup()
}

func (pk *PublicKey) NonceGroup() *znstar.RSAGroupUnknownOrder {
	nonceGroup, err := znstar.NewRSAGroupOfUnknownOrder(pk.group.N())
	if err != nil {
		panic(err)
	}
	return nonceGroup
}

func (pk *PublicKey) CiphertextGroup() *znstar.PaillierGroupUnknownOrder {
	return pk.group
}

func (pk *PublicKey) Equal(other *PublicKey) bool {
	if pk == nil || other == nil {
		return pk == other
	}
	return pk.group.Equal(other.group)
}

func (pk *PublicKey) HashCode() base.HashCode {
	return pk.group.Modulus().HashCode()
}

func (pk *PublicKey) MarshalCBOR() ([]byte, error) {
	dto := &publicKeyDTO{
		Group: pk.group,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal public key to CBOR")
	}
	return out, nil
}

func (pk *PublicKey) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*publicKeyDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal public key from CBOR")
	}
	newPk, err := NewPublicKey(dto.Group)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create public key from unmarshaled data")
	}
	*pk = *newPk
	return nil
}
