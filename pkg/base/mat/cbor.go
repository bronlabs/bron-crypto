package mat

import (
	"math/bits"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
)

// expectedDataLen returns rows*cols as an int, or ok=false if the product
// overflows int.
func expectedDataLen(rows, cols int) (int, bool) {
	if rows <= 0 || cols <= 0 {
		return 0, false
	}
	hi, lo := bits.Mul(uint(rows), uint(cols))
	if hi != 0 || lo > (^uint(0)>>1) {
		return 0, false
	}
	return int(lo), true
}

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
	expected, ok := expectedDataLen(dto.Rows, dto.Cols)
	if !ok {
		return ErrDimension.WithMessage("matrix dimensions overflow: %dx%d", dto.Rows, dto.Cols)
	}
	if len(dto.Data) != expected {
		return ErrFailed.WithMessage("data length does not match dimensions: got %d, expected %d", len(dto.Data), expected)
	}
	if slices.ContainsFunc(dto.Data, utils.IsNil) {
		return ErrFailed.WithMessage("data contains nil element")
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
	expected, ok := expectedDataLen(dto.Rows, dto.Cols)
	if !ok {
		return ErrDimension.WithMessage("matrix dimensions overflow: %dx%d", dto.Rows, dto.Cols)
	}
	if len(dto.Data) != expected {
		return ErrFailed.WithMessage("data length does not match dimensions: got %d, expected %d", len(dto.Data), expected)
	}
	if slices.ContainsFunc(dto.Data, utils.IsNil) {
		return ErrFailed.WithMessage("data contains nil element")
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
	expected, ok := expectedDataLen(dto.Size, dto.Size)
	if !ok {
		return ErrDimension.WithMessage("matrix dimensions overflow: %dx%d", dto.Size, dto.Size)
	}
	if len(dto.Data) != expected {
		return ErrFailed.WithMessage("data length does not match dimensions: got %d, expected %d", len(dto.Data), expected)
	}
	if slices.ContainsFunc(dto.Data, utils.IsNil) {
		return ErrFailed.WithMessage("data contains nil element")
	}
	m.init(dto.Size, dto.Size)
	copy(m.data(), dto.Data)
	return nil
}
