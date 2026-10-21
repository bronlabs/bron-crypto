package schnorrlike

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
)

// privateKeyDTO keeps the secret scalar and public point in distinct CBOR fields.
type privateKeyDTO[PKV GroupElement[PKV, S], S Scalar[S]] struct {
	SK S   `cbor:"privateKey"`
	PK PKV `cbor:"publicKey"`
}

// MarshalCBOR serialises the private scalar and corresponding public point.
// The output contains secret key material.
func (sk PrivateKey[PKV, S]) MarshalCBOR() ([]byte, error) {
	dto := privateKeyDTO[PKV, S]{SK: sk.Value(), PK: sk.PublicKey().Value()}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to serialise Schnorr private key")
	}
	return data, nil
}

// UnmarshalCBOR deserialises and validates a Schnorr private key.
// It rejects missing or invalid components and mismatched private and public keys.
func (sk *PrivateKey[PKV, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*privateKeyDTO[PKV, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to deserialise Schnorr private key")
	}
	if dto == nil {
		return signatures.ErrInvalidArgument.WithMessage("private key is nil")
	}
	publicKey, err := NewPublicKey(dto.PK)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to validate private key's public point")
	}
	decoded, err := NewPrivateKey(dto.SK, publicKey)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to validate private scalar")
	}
	if !publicKey.Group().ScalarBaseOp(decoded.Value()).Equal(publicKey.Value()) {
		return signatures.ErrInvalidArgument.WithMessage("private key does not match public key")
	}
	*sk = *decoded
	return nil
}
