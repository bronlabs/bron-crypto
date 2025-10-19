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
	BaseFieldNameG1 = "BLS12381Fp"
)

var (
	_ algebra.PrimeField[*BaseFieldElementG1]        = (*BaseFieldG1)(nil)
	_ algebra.PrimeFieldElement[*BaseFieldElementG1] = (*BaseFieldElementG1)(nil)
	_ encoding.BinaryMarshaler                       = (*BaseFieldElementG1)(nil)
	_ encoding.BinaryUnmarshaler                     = (*BaseFieldElementG1)(nil)

	baseFieldInstanceG1 *BaseFieldG1
	baseFieldInitOnceG1 sync.Once
	baseFieldOrderG1    *saferith.Modulus
)

type BaseFieldG1 struct {
	traits.PrimeFieldTrait[*bls12381Impl.Fp, *BaseFieldElementG1, BaseFieldElementG1]
}

func NewG1BaseField() *BaseFieldG1 {
	baseFieldInitOnceG1.Do(func() {
		baseFieldOrderG1 = saferith.ModulusFromBytes(sliceutils.Reversed(bls12381Impl.FpModulus[:]))
		baseFieldInstanceG1 = &BaseFieldG1{}
	})

	return baseFieldInstanceG1
}

func (f *BaseFieldG1) Name() string {
	return BaseFieldNameG1
}

func (f *BaseFieldG1) Order() cardinal.Cardinal {
	return cardinal.NewFromSaferith(baseFieldOrderG1.Nat())
}

func (f *BaseFieldG1) Characteristic() cardinal.Cardinal {
	return cardinal.NewFromSaferith(baseFieldOrderG1.Nat())
}

func (f *BaseFieldG1) Hash(bytes []byte) (*BaseFieldElementG1, error) {
	var e [1]bls12381Impl.Fp
	h2c.HashToField(e[:], bls12381Impl.G1CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveSuiteG1, bytes)

	var s BaseFieldElementG1
	s.V.Set(&e[0])
	return &s, nil
}

func (f *BaseFieldG1) ElementSize() int {
	return bls12381Impl.FpBytes
}

func (f *BaseFieldG1) WideElementSize() int {
	return bls12381Impl.FpWideBytes
}

func (f *BaseFieldG1) BitLen() int {
	return bls12381Impl.FpBits
}

func (f *BaseFieldG1) FromNat(n *numct.Nat) (*BaseFieldElementG1, error) {
	var v numct.Nat
	m, ok := numct.NewModulusOddPrime((*numct.Nat)(baseFieldOrderG1.Nat()))
	if ok == ct.False {
		return nil, errs.NewFailed("failed to create modulus")
	}
	m.Mod(&v, n)
	vBytes := v.Bytes()
	slices.Reverse(vBytes)
	var s BaseFieldElementG1
	if ok := s.V.SetBytesWide(vBytes); ok == ct.False {
		return nil, errs.NewFailed("failed to set scalar from nat")
	}
	return &s, nil
}

type BaseFieldElementG1 struct {
	traits.PrimeFieldElementTrait[*bls12381Impl.Fp, bls12381Impl.Fp, *BaseFieldElementG1, BaseFieldElementG1]
}

func (fe *BaseFieldElementG1) Structure() algebra.Structure[*BaseFieldElementG1] {
	return NewG1BaseField()
}

func (fe *BaseFieldElementG1) MarshalBinary() (data []byte, err error) {
	return fe.V.Bytes(), nil
}

func (fe *BaseFieldElementG1) UnmarshalBinary(data []byte) error {
	if ok := fe.V.SetBytes(data); ok == 0 {
		return errs.NewSerialisation("failed to unmarshal field element")
	}

	return nil
}
