package key_agreement

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

type privateKeyDTO[V algebra.UintLike[V]] struct {
	V V    `cbor:"v"`
	T Type `cbor:"t"`
}

func (sk *PrivateKey[V]) MarshalCBOR() ([]byte, error) {
	dto := &privateKeyDTO[V]{
		V: sk.v,
		T: sk.t,
	}
	return serde.MarshalCBOR(dto)
}

func (sk *PrivateKey[V]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[privateKeyDTO[V]](data)
	if err != nil {
		return errs2.Wrap(err).WithMessage("couldn't serialize private key")
	}
	if _, err := NewPrivateKey(dto.V, dto.T); err != nil {
		return errs2.Wrap(err).WithMessage("invalid private key")
	}
	sk.v = dto.V
	sk.t = dto.T
	return nil
}

type publicKeyDTO[V algebra.AbelianGroupElement[V, S], S algebra.UintLike[S]] struct {
	V V    `cbor:"v"`
	T Type `cbor:"t"`
}

func (pk *PublicKey[V, S]) MarshalCBOR() ([]byte, error) {
	dto := &publicKeyDTO[V, S]{
		V: pk.v,
		T: pk.t,
	}
	return serde.MarshalCBOR(dto)
}

func (pk *PublicKey[V, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[publicKeyDTO[V, S]](data)
	if err != nil {
		return errs2.Wrap(err).WithMessage("couldn't serialize public key")
	}
	if _, err := NewPublicKey(dto.V, dto.T); err != nil {
		return errs2.Wrap(err).WithMessage("invalid public key")
	}
	pk.v = dto.V
	pk.t = dto.T
	return nil
}

type sharedKeyDTO struct {
	V []byte `cbor:"v"`
	T Type   `cbor:"t"`
}

func (k *SharedKey) MarshalCBOR() ([]byte, error) {
	dto := &sharedKeyDTO{
		V: k.v,
		T: k.t,
	}
	return serde.MarshalCBOR(dto)
}

func (k *SharedKey) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[sharedKeyDTO](data)
	if err != nil {
		return errs2.Wrap(err).WithMessage("couldn't serialize shared key")
	}
	if _, err := NewSharedKey(dto.V, dto.T); err != nil {
		return errs2.Wrap(err).WithMessage("invalid shared key")
	}
	k.v = dto.V
	k.t = dto.T
	return nil
}
