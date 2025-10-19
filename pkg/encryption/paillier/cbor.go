package paillier

import (
	"github.com/fxamacker/cbor/v2"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
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

const (
	PlaintextTag  = 6001
	NonceTag      = 6002
	CiphertextTag = 6003
	PublicKeyTag  = 6004
	PrivateKeyTag = 6005
)

func init() {
	serde.Register[*Plaintext](PlaintextTag)
	serde.Register[*Nonce](NonceTag)
	serde.Register[*Ciphertext](CiphertextTag)
	serde.Register[*PublicKey](PublicKeyTag)
	serde.Register[*PrivateKey](PrivateKeyTag)
}

// Plaintext serialisation - reuse num.Int and num.NatPlus CBOR.
type plaintextDTO struct {
	V *num.Int     `cbor:"v"`
	N *num.NatPlus `cbor:"n"`
}

func (p *Plaintext) MarshalCBOR() ([]byte, error) {
	dto := &plaintextDTO{
		V: p.v,
		N: p.n,
	}
	data, err := serde.MarshalCBORTagged(dto, PlaintextTag)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal Plaintext")
	}
	return data, nil
}

func (p *Plaintext) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[plaintextDTO](data)
	if err != nil {
		return err
	}
	p.v = dto.V
	p.n = dto.N
	return nil
}

// Nonce serialisation - reuse znstar.Unit CBOR.
type nonceDTO struct {
	U znstar.Unit `cbor:"u"`
}

func (n *Nonce) MarshalCBOR() ([]byte, error) {
	dto := &nonceDTO{
		U: n.u,
	}
	data, err := serde.MarshalCBORTagged(dto, NonceTag)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal Nonce")
	}
	return data, nil
}

func (n *Nonce) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[nonceDTO](data)
	if err != nil {
		return err
	}
	n.u = dto.U
	return nil
}

// Ciphertext serialisation - reuse znstar.Unit CBOR.
type ciphertextDTO struct {
	U znstar.Unit `cbor:"u"`
}

func (c *Ciphertext) MarshalCBOR() ([]byte, error) {
	dto := &ciphertextDTO{
		U: c.u,
	}
	data, err := serde.MarshalCBORTagged(dto, CiphertextTag)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal Ciphertext")
	}
	return data, nil
}

func (c *Ciphertext) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[ciphertextDTO](data)
	if err != nil {
		return err
	}
	c.u = dto.U
	return nil
}

// PublicKey serialisation - reuse znstar.PaillierGroup CBOR.
type publicKeyDTO struct {
	Group znstar.PaillierGroup `cbor:"group"`
}

func (pk *PublicKey) MarshalCBOR() ([]byte, error) {
	dto := &publicKeyDTO{
		Group: pk.group,
	}
	data, err := serde.MarshalCBORTagged(dto, PublicKeyTag)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal PublicKey")
	}
	return data, nil
}

func (pk *PublicKey) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[publicKeyDTO](data)
	if err != nil {
		return err
	}
	pk.group = dto.Group
	// Spaces will be lazily initialised via cacheSpaces when accessed
	return nil
}

// PrivateKey serialisation - reuse znstar.PaillierGroupKnownOrder and numct.Nat CBOR.
type privateKeyDTO struct {
	Group znstar.PaillierGroupKnownOrder `cbor:"group"`
}

func (sk *PrivateKey) MarshalCBOR() ([]byte, error) {
	dto := &privateKeyDTO{
		Group: sk.group,
	}
	data, err := serde.MarshalCBORTagged(dto, PrivateKeyTag)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal PrivateKey")
	}
	return data, nil
}

func (sk *PrivateKey) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[privateKeyDTO](data)
	if err != nil {
		return err
	}
	sk.group = dto.Group
	// Initialise hp and hq before calling precompute
	sk.hp = numct.NewNat(0)
	sk.hq = numct.NewNat(0)
	sk.precompute()
	return nil
}
