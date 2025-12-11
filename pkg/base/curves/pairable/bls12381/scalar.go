package bls12381

import (
	"encoding"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	h2c "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

const (
	ScalarFieldName       = "BLS12381Fq"
	Hash2CurveScalarSuite = "BLS12381G1_XMD:SHA-256_SSWU_RO_SC_"
)

var (
	_ algebra.PrimeField[*Scalar]        = (*ScalarField)(nil)
	_ algebra.PrimeFieldElement[*Scalar] = (*Scalar)(nil)
	_ encoding.BinaryMarshaler           = (*Scalar)(nil)
	_ encoding.BinaryUnmarshaler         = (*Scalar)(nil)

	scalarFieldInitOnce sync.Once
	scalarFieldInstance *ScalarField
	scalarFieldOrder    *numct.Modulus
)

func scalarFieldInit() {
	scalarFieldOrder, _ = numct.NewModulusFromBytesBE(sliceutils.Reversed(bls12381Impl.FqModulus[:]))
	scalarFieldInstance = &ScalarField{}
}

type ScalarField struct {
	traits.PrimeFieldTrait[*bls12381Impl.Fq, *Scalar, Scalar]
}

func NewScalarField() *ScalarField {
	scalarFieldInitOnce.Do(scalarFieldInit)
	return scalarFieldInstance
}

func (*ScalarField) Name() string {
	return ScalarFieldName
}

func (*ScalarField) ElementSize() int {
	return bls12381Impl.FqBytes
}

func (*ScalarField) WideElementSize() int {
	return bls12381Impl.FqWideBytes
}

func (f *ScalarField) Characteristic() cardinal.Cardinal {
	return f.Order()
}

func (*ScalarField) Order() cardinal.Cardinal {
	return cardinal.NewFromNumeric(scalarFieldOrder)
}

func (*ScalarField) Hash(input []byte) (*Scalar, error) {
	var e [1]bls12381Impl.Fq
	h2c.HashToField(e[:], bls12381Impl.G1CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveScalarSuite, input)

	var s Scalar
	s.V.Set(&e[0])
	return &s, nil
}

func (f *ScalarField) FromBytesBEReduce(input []byte) (*Scalar, error) {
	var v numct.Nat
	var nNat numct.Nat
	nNat.SetBytes(input)
	scalarFieldOrder.Mod(&v, &nNat)
	vBytes := v.Bytes()
	return f.FromBytesBE(vBytes)
}

func (*ScalarField) BitLen() int {
	return bls12381Impl.FqBits
}

type Scalar struct {
	traits.PrimeFieldElementTrait[*bls12381Impl.Fq, bls12381Impl.Fq, *Scalar, Scalar]
}

func (s *Scalar) Structure() algebra.Structure[*Scalar] {
	return NewScalarField()
}

func (s *Scalar) MarshalBinary() ([]byte, error) {
	return s.V.Bytes(), nil
}

func (s *Scalar) UnmarshalBinary(data []byte) error {
	if ok := s.V.SetBytes(data); ok == 0 {
		return errs.NewSerialisation("cannot unmarshal scalar")
	}

	return nil
}
