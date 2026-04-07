package mat

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

type matrixDTO[S algebra.RingElement[S]] struct {
	Rows int `cbor:"rows"`
	Cols int `cbor:"cols"`
	Data []S `cbor:"data"`
}

// MarshalCBOR serialises the matrix to CBOR.
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

// UnmarshalCBOR deserialises the matrix from CBOR.
func (m *Matrix[S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*matrixDTO[S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal matrix")
	}
	if len(dto.Data) == 0 {
		return ErrFailed.WithMessage("empty data")
	}
	if dto.Rows <= 0 || dto.Cols <= 0 {
		return ErrDimension.WithMessage("matrix dimensions must be positive: got %dx%d", dto.Rows, dto.Cols)
	}
	if len(dto.Data) != dto.Rows*dto.Cols {
		return ErrFailed.WithMessage("data length does not match dimensions: got %d, expected %d", len(dto.Data), dto.Rows*dto.Cols)
	}
	m.init(dto.Rows, dto.Cols)
	copy(m.data(), dto.Data)
	return nil
}

type moduleValuedMatrixDTO[E algebra.ModuleElement[E, S], S algebra.RingElement[S]] struct {
	Rows int `cbor:"rows"`
	Cols int `cbor:"cols"`
	Data []E `cbor:"data"`
}

// MarshalCBOR serialises the module-valued matrix to CBOR.
func (m *ModuleValuedMatrix[E, S]) MarshalCBOR() ([]byte, error) {
	dto := &moduleValuedMatrixDTO[E, S]{
		Rows: m.rows(),
		Cols: m.cols(),
		Data: m.data(),
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal module-valued matrix")
	}
	return data, nil
}

// UnmarshalCBOR deserialises the module-valued matrix from CBOR.
func (m *ModuleValuedMatrix[E, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*moduleValuedMatrixDTO[E, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal module-valued matrix")
	}
	if len(dto.Data) == 0 {
		return ErrFailed.WithMessage("empty data")
	}
	if dto.Rows <= 0 || dto.Cols <= 0 {
		return ErrDimension.WithMessage("matrix dimensions must be positive: got %dx%d", dto.Rows, dto.Cols)
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

// MarshalCBOR serialises the square matrix to CBOR.
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

// UnmarshalCBOR deserialises the square matrix from CBOR.
func (m *SquareMatrix[S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*squareMatrixDTO[S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal square matrix")
	}
	if len(dto.Data) == 0 {
		return ErrFailed.WithMessage("empty data")
	}
	if dto.Size <= 0 {
		return ErrDimension.WithMessage("matrix dimensions must be positive: got %dx%d", dto.Size, dto.Size)
	}
	if len(dto.Data) != dto.Size*dto.Size {
		return ErrFailed.WithMessage("data length does not match dimensions: got %d, expected %d", len(dto.Data), dto.Size*dto.Size)
	}
	m.init(dto.Size, dto.Size)
	copy(m.data(), dto.Data)
	return nil
}
