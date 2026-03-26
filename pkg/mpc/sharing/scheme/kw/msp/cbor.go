package msp

import (
	"maps"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/errs-go/errs"
)

type mspDTO[E algebra.FiniteFieldElement[E]] struct {
	Matrix        *mat.Matrix[E]
	RowsToHolders map[int]ID
}

func (m *MSP[E]) MarshalCBOR() ([]byte, error) {
	dto := mspDTO[E]{
		Matrix:        m.matrix,
		RowsToHolders: maps.Collect(m.rowsToHolders.Iter()),
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal MSP to CBOR")
	}
	return out, nil
}

func (m *MSP[E]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*mspDTO[E]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal MSP from CBOR")
	}
	msp, err := NewMSP(dto.Matrix, dto.RowsToHolders)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid MSP data in CBOR")
	}
	m.matrix = msp.matrix
	m.rowsToHolders = msp.rowsToHolders
	m.holdersToRows = msp.holdersToRows
	return nil
}
