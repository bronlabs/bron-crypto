package mat

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/errs-go/errs"
)

type matrixDTO[S algebra.RingElement[S]] struct {
	Rows int `cbor:"rows"`
	Cols int `cbor:"cols"`
	Data []S `cbor:"data"`
}

func (m *Matrix[S]) MarshalCBOR() ([]byte, error) {
	dto := &matrixDTO[S]{
		Rows: m.rows(),
		Cols: m.cols(),
		Data: m.data(),
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal matrix")
	}
	return data, nil
}

func (m *Matrix[S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*matrixDTO[S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal matrix")
	}
	if len(dto.Data) == 0 {
		return errs.Wrap(err).WithMessage("empty data")
	}
	if len(dto.Data) != dto.Rows*dto.Cols {
		return ErrFailed.WithMessage("data length does not match dimensions: got %d, expected %d", len(dto.Data), dto.Rows*dto.Cols)
	}
	m.init(dto.Rows, dto.Cols)
	copy(m.data(), dto.Data)
	return nil
}

type squareMatrixDTO[S algebra.RingElement[S]] struct {
	Size int `cbor:"size"`
	Data []S `cbor:"data"`
}

func (m *SquareMatrix[S]) MarshalCBOR() ([]byte, error) {
	dto := &squareMatrixDTO[S]{
		Size: m.rows(),
		Data: m.data(),
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal square matrix")
	}
	return data, nil
}

func (m *SquareMatrix[S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*squareMatrixDTO[S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal square matrix")
	}
	if len(dto.Data) == 0 {
		return errs.Wrap(err).WithMessage("empty data")
	}
	if len(dto.Data) != dto.Size*dto.Size {
		return ErrFailed.WithMessage("data length does not match dimensions: got %d, expected %d", len(dto.Data), dto.Size*dto.Size)
	}
	m.init(dto.Size, dto.Size)
	copy(m.data(), dto.Data)
	return nil
}
