package dhc

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/errs-go/pkg/errs"
)

type privateKeyDTO struct {
	V []byte `cbor:"seed"`
}

func (sk *PrivateKey) MarshalCBOR() ([]byte, error) {
	dto := &privateKeyDTO{
		V: sk.v,
	}
	return serde.MarshalCBOR(dto)
}

func (sk *PrivateKey) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[privateKeyDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not serialise private key")
	}
	if _, err := NewPrivateKey(dto.V); err != nil {
		return errs.Wrap(err).WithMessage("invalid private key")
	}
	sk.v = slices.Clone(dto.V)
	return nil
}

type extendedPrivateKeyDTO[S algebra.PrimeFieldElement[S]] struct {
	V []byte `cbor:"seed"`
	S S      `cbor:"s"`
}

func (esk *ExtendedPrivateKey[S]) MarshalCBOR() ([]byte, error) {
	dto := &extendedPrivateKeyDTO[S]{
		V: esk.v,
		S: esk.s,
	}
	return serde.MarshalCBOR(dto)
}

func (esk *ExtendedPrivateKey[S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[extendedPrivateKeyDTO[S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not serialise extended private key")
	}
	dtoSk, err := NewPrivateKey(dto.V)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid private key")
	}
	dtoSf := algebra.StructureMustBeAs[algebra.PrimeField[S]](dto.S.Structure())
	var ok bool
	if isFromCurve25519(dtoSf.Name()) {
		expected, err := ExtendPrivateKey(dtoSk, dtoSf)
		if err != nil {
			return errs.Wrap(err).WithMessage("invalid extended private key")
		}
		ok = expected.s.Equal(dto.S)
	} else {
		var s S
		s, err = dtoSf.FromBytes(dto.V)
		if err != nil {
			return errs.Wrap(err).WithMessage("invalid extended private key")
		}
		ok = s.Equal(dto.S)
	}
	if !ok {
		return ErrValidation.WithMessage("invalid extended private key scalar")
	}
	esk.v = slices.Clone(dto.V)
	esk.s = dto.S
	return nil
}
