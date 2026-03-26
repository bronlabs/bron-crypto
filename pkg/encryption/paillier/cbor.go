package paillier

import (
	"sync"

	"github.com/fxamacker/cbor/v2"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

var (
	_ cbor.Marshaler   = (*Plaintext)(nil)
	_ cbor.Unmarshaler = (*Plaintext)(nil)
	_ cbor.Marshaler   = (*Nonce)(nil)
	_ cbor.Unmarshaler = (*Nonce)(nil)
	_ cbor.Marshaler   = (*Ciphertext)(nil)
	_ cbor.Unmarshaler = (*Ciphertext)(nil)
	_ cbor.Marshaler   = (*PublicKey)(nil)
	_ cbor.Unmarshaler = (*PublicKey)(nil)
	_ cbor.Marshaler   = (*PrivateKey)(nil)
	_ cbor.Unmarshaler = (*PrivateKey)(nil)
)

// Plaintext serialisation - reuse num.Int and num.NatPlus CBOR.
type plaintextDTO struct {
	V *num.Int     `cbor:"v"`
	N *num.NatPlus `cbor:"n"`
}

// MarshalCBOR serialises the plaintext to CBOR format.
func (pt *Plaintext) MarshalCBOR() ([]byte, error) {
	dto := &plaintextDTO{
		V: pt.v,
		N: pt.n,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return data, nil
}

// UnmarshalCBOR deserializes the plaintext from CBOR format.
func (pt *Plaintext) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[plaintextDTO](data)
	if err != nil {
		return errs.Wrap(err)
	}

	if dto.V == nil || dto.N == nil {
		return ErrInvalidArgument.WithMessage("plaintext must have both value and modulus, or neither")
	}
	if !dto.V.IsInRangeSymmetric(dto.N) {
		return ErrInvalidRange.WithMessage("deserialized plaintext value is outside symmetric range")
	}

	space, err := NewPlaintextSpace(dto.N)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create plaintext space")
	}
	pt2, err := space.FromInt(dto.V.Value())
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create plaintext")
	}

	*pt = *pt2
	return nil
}

// Nonce serialisation - reuse znstar.Unit CBOR.
type nonceDTO struct {
	U *znstar.RSAGroupElementUnknownOrder `cbor:"u"`
}

// MarshalCBOR serialises the nonce to CBOR format.
func (n *Nonce) MarshalCBOR() ([]byte, error) {
	dto := &nonceDTO{
		U: n.u,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return data, nil
}

// UnmarshalCBOR deserializes the nonce from CBOR format.
func (n *Nonce) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[nonceDTO](data)
	if err != nil {
		return errs.Wrap(err)
	}
	if dto.U == nil {
		return ErrInvalidArgument.WithMessage("nonce is nil")
	}

	n.u = dto.U
	return nil
}

// Ciphertext serialisation - reuse znstar.Unit CBOR.
type ciphertextDTO struct {
	U *znstar.PaillierGroupElementUnknownOrder `cbor:"u"`
}

// MarshalCBOR serialises the ciphertext to CBOR format.
func (ctx *Ciphertext) MarshalCBOR() ([]byte, error) {
	dto := &ciphertextDTO{
		U: ctx.u,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return data, nil
}

// UnmarshalCBOR deserializes the ciphertext from CBOR format.
func (ctx *Ciphertext) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[ciphertextDTO](data)
	if err != nil {
		return errs.Wrap(err)
	}
	if dto.U == nil {
		return ErrInvalidArgument.WithMessage("ciphertext is nil")
	}

	ctx.u = dto.U
	return nil
}

// PublicKey serialisation - reuse znstar.PaillierGroup CBOR.
type publicKeyDTO struct {
	Group *znstar.PaillierGroupUnknownOrder `cbor:"group"`
}

// MarshalCBOR serialises the public key to CBOR format.
func (pk *PublicKey) MarshalCBOR() ([]byte, error) {
	dto := &publicKeyDTO{
		Group: pk.group,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return data, nil
}

// UnmarshalCBOR deserializes the public key from CBOR format.
func (pk *PublicKey) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[publicKeyDTO](data)
	if err != nil {
		return errs.Wrap(err)
	}
	pkPtr, err := NewPublicKey(dto.Group)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create public key")
	}
	pk.group = pkPtr.Group()
	pk.nonceSpace = nil
	pk.plaintextSpace = nil
	pk.ciphertextSpace = nil
	pk.once = sync.Once{}

	// Spaces will be lazily initialised via cacheSpaces when accessed
	return nil
}

// PrivateKey serialisation - reuse znstar.PaillierGroupKnownOrder and numct.Nat CBOR.
type privateKeyDTO struct {
	Group *znstar.PaillierGroupKnownOrder `cbor:"group"`
}

// MarshalCBOR serialises the private key to CBOR format.
func (sk *PrivateKey) MarshalCBOR() ([]byte, error) {
	dto := &privateKeyDTO{
		Group: sk.group,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return data, nil
}

// UnmarshalCBOR deserializes the private key from CBOR format.
func (sk *PrivateKey) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[privateKeyDTO](data)
	if err != nil {
		return errs.Wrap(err)
	}

	skPtr, err := NewPrivateKey(dto.Group)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create private key")
	}

	sk.group = skPtr.Group()
	sk.hp = numct.NewNat(0)
	sk.hq = numct.NewNat(0)
	sk.pk = nil
	sk.once = sync.Once{}
	sk.precompute()
	return nil
}
