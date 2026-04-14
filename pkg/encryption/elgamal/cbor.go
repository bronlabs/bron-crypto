package elgamal

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
)

type publicKeyDTO[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]] struct {
	V E `cbor:"v"`
}

func (pk *PublicKey[E, S]) MarshalCBOR() ([]byte, error) {
	if pk == nil {
		return nil, ErrIsNil.WithMessage("public key")
	}
	dto := publicKeyDTO[E, S]{V: pk.v}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal public key to cbor")
	}
	return data, nil
}

func (pk *PublicKey[E, S]) UnmarshalCBOR(data []byte) error {
	if pk == nil {
		return ErrIsNil.WithMessage("public key")
	}
	dto, err := serde.UnmarshalCBOR[publicKeyDTO[E, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal public key from cbor")
	}
	newPk, err := NewPublicKey(dto.V)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create public key from deserialized value")
	}
	pk.v = newPk.v
	return nil
}

type privateKeyDTO[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]] struct {
	V  S                `cbor:"v"`
	PK *PublicKey[E, S] `cbor:"pk"`
}

func (sk *PrivateKey[E, S]) MarshalCBOR() ([]byte, error) {
	if sk == nil {
		return nil, ErrIsNil.WithMessage("private key")
	}
	dto := privateKeyDTO[E, S]{V: sk.v, PK: &sk.pk}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal private key to cbor")
	}
	return data, nil
}

func (sk *PrivateKey[E, S]) UnmarshalCBOR(data []byte) error {
	if sk == nil {
		return ErrIsNil.WithMessage("private key")
	}
	dto, err := serde.UnmarshalCBOR[privateKeyDTO[E, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal private key from cbor")
	}
	if dto.PK == nil {
		return ErrIsNil.WithMessage("deserialized public key")
	}
	newSk, err := NewPrivateKey(dto.PK.Group(), dto.V)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create private key from deserialized value")
	}
	if !newSk.pk.Equal(dto.PK) {
		return ErrValue.WithMessage("deserialized private key's public key does not match the deserialized public key")
	}
	sk.v = newSk.v
	sk.pk = newSk.pk
	return nil
}

type plaintextDTO[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]] struct {
	V E `cbor:"v"`
}

func (p *Plaintext[E, S]) MarshalCBOR() ([]byte, error) {
	if p == nil {
		return nil, ErrIsNil.WithMessage("plaintext")
	}
	dto := plaintextDTO[E, S]{V: p.v}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal plaintext to cbor")
	}
	return data, nil
}

func (p *Plaintext[E, S]) UnmarshalCBOR(data []byte) error {
	if p == nil {
		return ErrIsNil.WithMessage("plaintext")
	}
	dto, err := serde.UnmarshalCBOR[plaintextDTO[E, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal plaintext from cbor")
	}
	newP, err := NewPlaintext(dto.V)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create plaintext from deserialized value")
	}
	p.v = newP.v
	return nil
}

type nonceDTO[S algebra.UintLike[S]] struct {
	V S `cbor:"v"`
}

func (n *Nonce[S]) MarshalCBOR() ([]byte, error) {
	if n == nil {
		return nil, ErrIsNil.WithMessage("nonce")
	}
	dto := nonceDTO[S]{V: n.v}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal nonce to cbor")
	}
	return data, nil
}

func (n *Nonce[S]) UnmarshalCBOR(data []byte) error {
	if n == nil {
		return ErrIsNil.WithMessage("nonce")
	}
	dto, err := serde.UnmarshalCBOR[nonceDTO[S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal nonce from cbor")
	}
	newN, err := NewNonce(dto.V)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create nonce from deserialized value")
	}
	n.v = newN.v
	return nil
}

type ciphertextDTO[E FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]] struct {
	V [2]E `cbor:"v"`
}

func (c *Ciphertext[E, S]) MarshalCBOR() ([]byte, error) {
	if c == nil {
		return nil, ErrIsNil.WithMessage("ciphertext")
	}
	dto := ciphertextDTO[E, S]{V: [2]E{c.v.Components()[0], c.v.Components()[1]}}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal ciphertext to cbor")
	}
	return data, nil
}

func (c *Ciphertext[E, S]) UnmarshalCBOR(data []byte) error {
	if c == nil {
		return ErrIsNil.WithMessage("ciphertext")
	}
	dto, err := serde.UnmarshalCBOR[ciphertextDTO[E, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal ciphertext from cbor")
	}
	if utils.IsNil(dto.V[0]) || utils.IsNil(dto.V[1]) {
		return ErrIsNil.WithMessage("ciphertext component")
	}
	if !dto.V[0].IsTorsionFree() || !dto.V[1].IsTorsionFree() {
		return ErrSubGroupMembership.WithMessage("ciphertext component is not torsion free")
	}
	// The second component can be identity if the message happens to be -h^r. The first one can never be identity for nonzero nonce.
	if dto.V[0].IsOpIdentity() {
		return ErrSubGroupMembership.WithMessage("invalid ciphertext: first component is identity")
	}
	newC, err := NewCiphertext(dto.V[0], dto.V[1])
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create ciphertext from deserialized value")
	}
	c.v = newC.v
	return nil
}
