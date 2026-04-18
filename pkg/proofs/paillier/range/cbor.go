package paillierrange

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
)

type witnessDTO struct {
	M *paillier.Plaintext `cbor:"m"`
	R *paillier.Nonce     `cbor:"r"`
}

func (w *Witness) MarshalCBOR() ([]byte, error) {
	dto := witnessDTO{
		M: w.m,
		R: w.r,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("couldn't marshal witness to CBOR")
	}
	return out, nil
}

func (w *Witness) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*witnessDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("couldn't unmarshal witness from CBOR")
	}
	witness, err := NewWitness(dto.M, dto.R)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid witness data")
	}
	*w = *witness
	return nil
}

type statementDTO struct {
	C *paillier.Ciphertext `cbor:"c"`
}

func (s *Statement) MarshalCBOR() ([]byte, error) {
	dto := statementDTO{
		C: s.c,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("couldn't marshal statement to CBOR")
	}
	return out, nil
}

func (s *Statement) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*statementDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("couldn't unmarshal statement from CBOR")
	}
	statement, err := NewStatement(dto.C)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid statement data")
	}
	*s = *statement
	return nil
}
