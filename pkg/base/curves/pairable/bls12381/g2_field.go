package bls12381

import (
	"encoding"
	"slices"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	h2c "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381/impl"
	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
)

const (
	// BaseFieldNameG2 is the G2 base field name.
	BaseFieldNameG2 = "BLS12381Fp2"
)

var (
	_ algebra.Field[*BaseFieldElementG2]        = (*BaseFieldG2)(nil)
	_ algebra.FieldElement[*BaseFieldElementG2] = (*BaseFieldElementG2)(nil)
	_ encoding.BinaryMarshaler                  = (*BaseFieldElementG2)(nil)
	_ encoding.BinaryUnmarshaler                = (*BaseFieldElementG2)(nil)

	baseFieldInstanceG2 *BaseFieldG2
	baseFieldInitOnceG2 sync.Once
)

// BaseFieldG2 represents the base field for G2.
type BaseFieldG2 struct {
	traits.FiniteFieldTrait[*bls12381Impl.Fp2, *BaseFieldElementG2, BaseFieldElementG2]
}

// NewG2BaseField returns a new instance.
func NewG2BaseField() *BaseFieldG2 {
	baseFieldInitOnceG2.Do(func() {
		//nolint:exhaustruct // no need for a trait
		baseFieldInstanceG2 = &BaseFieldG2{}
	})

	return baseFieldInstanceG2
}

// Hash maps input bytes to an element or point.
func (*BaseFieldG2) Hash(bytes []byte) (*BaseFieldElementG2, error) {
	var e [1]bls12381Impl.Fp2
	h2c.HashToField(e[:], bls12381Impl.G2CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveSuiteG2, bytes)

	var s BaseFieldElementG2
	s.V.Set(&e[0])
	return &s, nil
}

// Name returns the name of the structure.
func (*BaseFieldG2) Name() string {
	return BaseFieldNameG2
}

// IsDomain reports whether the field forms an integral domain.
func (*BaseFieldG2) IsDomain() bool {
	return true
}

// Order returns the group or field order.
func (*BaseFieldG2) Order() cardinal.Cardinal {
	return NewG1BaseField().Order().Add(NewG1BaseField().Order())
}

// Characteristic returns the field characteristic.
func (*BaseFieldG2) Characteristic() cardinal.Cardinal {
	return NewG1BaseField().Characteristic()
}

// ExtensionDegree returns the field extension degree.
func (*BaseFieldG2) ExtensionDegree() uint {
	return 2
}

// FromBytes decodes an element from bytes.
func (f *BaseFieldG2) FromBytes(data []byte) (*BaseFieldElementG2, error) {
	if len(data) != f.ElementSize() {
		return nil, curves.ErrInvalidLength.WithMessage("invalid data, Length is %d", len(data))
	}
	components := make([][]byte, 2)
	componentSize := f.ElementSize() / 2
	components[0] = data[:componentSize]
	components[1] = data[componentSize:]
	out, err := f.FromComponentsBytes(components)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to convert bytes into field element")
	}
	return out, nil
}

// FromWideBytes decodes an element from wide bytes.
func (*BaseFieldG2) FromWideBytes(data []byte) (*BaseFieldElementG2, error) {
	// TODO
	panic("implement me")
}

// ElementSize returns the element size in bytes.
func (*BaseFieldG2) ElementSize() int {
	return 2 * bls12381Impl.FpBytes
}

// WideElementSize returns the wide element size in bytes.
func (*BaseFieldG2) WideElementSize() int {
	return 2 * bls12381Impl.FpWideBytes
}

// BaseFieldElementG2 represents an element of the G2 base field.
type BaseFieldElementG2 struct {
	traits.FiniteFieldElementTrait[*bls12381Impl.Fp2, bls12381Impl.Fp2, *BaseFieldElementG2, BaseFieldElementG2]
}

// Structure returns the algebraic structure for the receiver.
func (*BaseFieldElementG2) Structure() algebra.Structure[*BaseFieldElementG2] {
	return NewG2BaseField()
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (fe *BaseFieldElementG2) MarshalBinary() ([]byte, error) {
	return slices.Concat(fe.V.U1.Bytes(), fe.V.U0.Bytes()), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (fe *BaseFieldElementG2) UnmarshalBinary(data []byte) error {
	if ok := fe.V.U1.SetBytes(data[:bls12381Impl.FpBytes]); ok == 0 {
		return curves.ErrSerialisation.WithMessage("invalid data")
	}
	if ok := fe.V.U0.SetBytes(data[bls12381Impl.FpBytes:]); ok == 0 {
		return curves.ErrSerialisation.WithMessage("invalid data")
	}
	return nil
}
