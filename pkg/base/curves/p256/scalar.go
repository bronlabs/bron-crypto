package p256

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
	k256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/k256/impl"
	p256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/p256/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

const (
	ScalarFieldName = "P256Fq"
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
	orderBytes := make([]byte, len(p256Impl.FqModulus))
	copy(orderBytes, p256Impl.FqModulus[:])
	slices.Reverse(orderBytes)
	scalarFieldOrder = saferith.ModulusFromBytes(orderBytes)
	scalarFieldInstance = &ScalarField{}
}

type ScalarField struct {
	traits.PrimeFieldTrait[*p256Impl.Fq, *Scalar, Scalar]
}

func NewScalarField() *ScalarField {
	scalarFieldInitOnce.Do(scalarFieldInit)
	return scalarFieldInstance
}

func (f *ScalarField) Name() string {
	return ScalarFieldName
}

func (f *ScalarField) Order() cardinal.Cardinal {
	return cardinal.NewFromSaferith(scalarFieldOrder.Nat())
}

func (f *ScalarField) Characteristic() cardinal.Cardinal {
	return cardinal.NewFromSaferith(scalarFieldOrder.Nat())
}

func (f *ScalarField) Hash(bytes []byte) (*Scalar, error) {
	var e [1]p256Impl.Fq
	h2c.HashToField(e[:], p256Impl.CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveScalarSuite, bytes)

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

func (f *ScalarField) ElementSize() int {
	return k256Impl.FqBytes
}

func (f *ScalarField) WideElementSize() int {
	return k256Impl.FqWideBytes
}

func (f *ScalarField) BitLen() int {
	return p256Impl.FqBits
}

type Scalar struct {
	traits.PrimeFieldElementTrait[*p256Impl.Fq, p256Impl.Fq, *Scalar, Scalar]
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
