package bls12381

import (
	"encoding"
	"slices"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
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
	scalarFieldOrder    *saferith.Modulus
)

func scalarFieldInit() {
	scalarFieldOrder = saferith.ModulusFromBytes(sliceutils.Reversed(bls12381Impl.FqModulus[:]))
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
	return cardinal.NewFromSaferith(scalarFieldOrder.Nat())
}

func (*ScalarField) Hash(input []byte) (*Scalar, error) {
	var e [1]bls12381Impl.Fq
	h2c.HashToField(e[:], bls12381Impl.G1CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveScalarSuite, input)

	var s Scalar
	s.V.Set(&e[0])
	return &s, nil
}

func (f *ScalarField) FromNat(n *numct.Nat) (*Scalar, error) {
	var v numct.Nat
	m, ok := numct.NewModulusOddPrime((*numct.Nat)(scalarFieldOrder.Nat()))
	if ok == ct.False {
		return nil, errs.NewFailed("failed to create modulus")
	}
	m.Mod(&v, n)
	vBytes := v.Bytes()
	slices.Reverse(vBytes)
	var s Scalar
	if ok := s.V.SetBytesWide(vBytes); ok == ct.False {
		return nil, errs.NewFailed("failed to set scalar from nat")
	}
	return &s, nil
}

func (f *ScalarField) FromNumeric(n algebra.Numeric) (*Scalar, error) {
	var v numct.Nat
	m, ok := numct.NewModulusOddPrime((*numct.Nat)(scalarFieldOrder.Nat()))
	if ok == ct.False {
		return nil, errs.NewFailed("failed to create modulus")
	}
	var nNat numct.Nat
	nNat.SetBytes(n.BytesBE())
	m.Mod(&v, &nNat)
	vBytes := v.Bytes()
	slices.Reverse(vBytes)
	var s Scalar
	if ok := s.V.SetBytesWide(vBytes); ok == ct.False {
		return nil, errs.NewFailed("failed to set scalar from numeric")
	}
	return &s, nil
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
