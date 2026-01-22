package paillier

import (
	"github.com/fxamacker/cbor/v2"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/errs-go/pkg/errs"
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
		return err
	}
	pt.v = dto.V
	pt.n = dto.N
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
		return err
	}
	n.u = dto.U
	return nil
}

// Ciphertext serialisation - reuse znstar.Unit CBOR.
type ciphertextDTO struct {
	U *znstar.PaillierGroupElementUnknownOrder `cbor:"u"`
}

// MarshalCBOR serialises the ciphertext to CBOR format.
func (ct *Ciphertext) MarshalCBOR() ([]byte, error) {
	dto := &ciphertextDTO{
		U: ct.u,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return data, nil
}

// UnmarshalCBOR deserializes the ciphertext from CBOR format.
func (ct *Ciphertext) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[ciphertextDTO](data)
	if err != nil {
		return err
	}
	ct.u = dto.U
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
		return err
	}
	pk.group = dto.Group
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
		return err
	}
	sk.group = dto.Group
	// Initialise hp and hq before calling precompute
	sk.hp = numct.NewNat(0)
	sk.hq = numct.NewNat(0)
	sk.precompute()
	return nil
}
