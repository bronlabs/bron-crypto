package bls12381

import (
	"slices"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/num/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/h2c"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

const (
	BaseFieldNameG2 = "BLS12381Fp2"
)

var (
	_ algebra.FiniteField[*BaseFieldElementG2]        = (*BaseFieldG2)(nil)
	_ algebra.FiniteFieldElement[*BaseFieldElementG2] = (*BaseFieldElementG2)(nil)

	baseFieldInstanceG2 *BaseFieldG2
	baseFieldInitOnceG2 sync.Once
)

type BaseFieldG2 struct {
	traits.FiniteFieldTrait[*bls12381Impl.Fp2, *BaseFieldElementG2, BaseFieldElementG2]
}

func NewG2BaseField() *BaseFieldG2 {
	baseFieldInitOnceG2.Do(func() {
		baseFieldInstanceG2 = &BaseFieldG2{}
	})

	return baseFieldInstanceG2
}

func (f *BaseFieldG2) Hash(bytes []byte) (*BaseFieldElementG2, error) {
	var e [1]bls12381Impl.Fp2
	h2c.HashToField(e[:], bls12381Impl.G2CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveSuiteG2, bytes)

	var s BaseFieldElementG2
	s.V.Set(&e[0])
	return &s, nil
}

func (f *BaseFieldG2) Name() string {
	return BaseFieldNameG2
}

func (f *BaseFieldG2) IsDomain() bool {
	return true
}

func (f *BaseFieldG2) Order() cardinal.Cardinal {
	return NewG1BaseField().Order().Add(NewG1BaseField().Order())
}

func (f *BaseFieldG2) Characteristic() cardinal.Cardinal {
	return NewG1BaseField().Characteristic()
}

func (f *BaseFieldG2) ExtensionDegree() uint {
	return 2
}

func (f *BaseFieldG2) FromBytes(data []byte) (*BaseFieldElementG2, error) {
	if len(data) != f.ElementSize() {
		return nil, errs.NewLength("invalid data, Length is %d", len(data))
	}
	components := make([][]byte, 2)
	componentSize := f.ElementSize() / 2
	components[0] = data[:componentSize]
	components[1] = data[componentSize:]
	return f.FromComponentsBytes(components)
}

func (f *BaseFieldG2) FromWideBytes(data []byte) (*BaseFieldElementG2, error) {
	// TODO
	panic("implement me")
}

func (f *BaseFieldG2) ElementSize() int {
	return 2 * bls12381Impl.FpBytes
}

func (f *BaseFieldG2) WideElementSize() int {
	return 2 * bls12381Impl.FpWideBytes
}

type BaseFieldElementG2 struct {
	traits.FiniteFieldElementTrait[*bls12381Impl.Fp2, bls12381Impl.Fp2, *BaseFieldElementG2, BaseFieldElementG2]
}

func (fe *BaseFieldElementG2) Structure() algebra.Structure[*BaseFieldElementG2] {
	return NewG2BaseField()
}

func (fe *BaseFieldElementG2) MarshalBinary() ([]byte, error) {
	return slices.Concat(fe.V.U1.Bytes(), fe.V.U0.Bytes()), nil
}

func (fe *BaseFieldElementG2) UnmarshalBinary(data []byte) error {
	if ok := fe.V.U1.SetBytes(data[:bls12381Impl.FpBytes]); ok == 0 {
		return errs.NewSerialisation("invalid data")
	}
	if ok := fe.V.U0.SetBytes(data[bls12381Impl.FpBytes:]); ok == 0 {
		return errs.NewSerialisation("invalid data")
	}
	return nil
}
