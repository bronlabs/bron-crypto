package k256

import (
	"encoding"
	"slices"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/universal"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl"
	h2c "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	k256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/k256/impl"
	"github.com/cronokirby/saferith"
)

const (
	ScalarFieldName = "secp256k1Fq"
)

var (
	_ algebra.PrimeField[*Scalar]        = (*ScalarField)(nil)
	_ algebra.PrimeFieldElement[*Scalar] = (*Scalar)(nil)
	_ encoding.BinaryMarshaler           = (*Scalar)(nil)
	_ encoding.BinaryUnmarshaler         = (*Scalar)(nil)

	scalarFieldInitOnce      sync.Once
	scalarFieldInstance      *ScalarField
	scalarFieldModelInitOnce sync.Once
	scalarFieldModelInstance *universal.Model[*Scalar]
	scalarFieldOrder         *saferith.Modulus
)

func scalarFieldInit() {
	orderBytes := make([]byte, len(k256Impl.FqModulus))
	copy(orderBytes, k256Impl.FqModulus[:])
	slices.Reverse(orderBytes)
	scalarFieldOrder = saferith.ModulusFromBytes(orderBytes)
	scalarFieldInstance = &ScalarField{}
}

type ScalarField struct {
	traits.PrimeFieldTrait[*k256Impl.Fq, *Scalar, Scalar]
}

func NewScalarField() *ScalarField {
	scalarFieldInitOnce.Do(scalarFieldInit)
	return scalarFieldInstance
}

func ScalarFieldModel() *universal.Model[*Scalar] {
	scalarFieldModelInitOnce.Do(func() {
		var err error
		scalarFieldModelInstance, err = impl.ScalarFieldModel(
			NewScalarField(),
		)
		if err != nil {
			panic(err)
		}
	})
	return scalarFieldModelInstance
}

func (f *ScalarField) Name() string {
	return ScalarFieldName
}

func (f *ScalarField) Model() *universal.Model[*Scalar] {
	return ScalarFieldModel()
}

func (f *ScalarField) Order() cardinal.Cardinal {
	return cardinal.NewFromNat(scalarFieldOrder.Nat())
}

func (f *ScalarField) Characteristic() cardinal.Cardinal {
	return cardinal.NewFromNat(scalarFieldOrder.Nat())
}

func (f *ScalarField) Hash(bytes []byte) (*Scalar, error) {
	var e [1]k256Impl.Fq
	h2c.HashToField(e[:], k256Impl.CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveScalarSuite, bytes)

	var s Scalar
	s.V.Set(&e[0])
	return &s, nil
}

func (f *ScalarField) ElementSize() int {
	return k256Impl.FqBytes
}

func (f *ScalarField) WideElementSize() int {
	return k256Impl.FqWideBytes
}

func (f *ScalarField) BitLen() int {
	return k256Impl.FqBits
}

type Scalar struct {
	traits.PrimeFieldElementTrait[*k256Impl.Fq, k256Impl.Fq, *Scalar, Scalar]
}

func (fe *Scalar) Structure() algebra.Structure[*Scalar] {
	return NewScalarField()
}

func (fe *Scalar) MarshalBinary() (data []byte, err error) {
	return fe.V.Bytes(), nil
}

func (fe *Scalar) UnmarshalBinary(data []byte) error {
	if ok := fe.V.SetBytes(data); ok == 0 {
		return errs.NewSerialisation("failed to unmarshal field element")
	}

	return nil
}
