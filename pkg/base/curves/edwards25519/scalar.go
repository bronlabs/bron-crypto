package edwards25519

import (
	"encoding"
	"slices"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	edwards25519Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519/impl"
	h2c "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

const (
	ScalarFieldName = "curve25519Fq"
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
	scalarFieldOrder = saferith.ModulusFromBytes(sliceutils.Reversed(edwards25519Impl.FqModulus[:]))
	scalarFieldInstance = &ScalarField{}
}

type ScalarField struct {
	traits.PrimeFieldTrait[*edwards25519Impl.Fq, *Scalar, Scalar]
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
	var e [1]edwards25519Impl.Fq
	h2c.HashToField(e[:], edwards25519Impl.CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveScalarSuite, bytes)

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

func (f *ScalarField) ElementSize() int {
	return edwards25519Impl.FqBytes
}

func (f *ScalarField) WideElementSize() int {
	return edwards25519Impl.FqWideBytes
}

func (f *ScalarField) BitLen() int {
	return edwards25519Impl.FqBits
}

func (f *ScalarField) FromClampedBytes(data []byte) (*Scalar, error) {
	if len(data) != edwards25519Impl.FqBytes {
		return nil, errs.NewLength("invalid input")
	}

	var clone [32]byte
	copy(clone[:], data)
	clone[0] &= 248
	clone[31] &= 127
	clone[31] |= 64

	var s Scalar
	if ok := s.V.SetBytesWide(clone[:]); ok == ct.False {
		return nil, errs.NewFailed("failed to set scalar from bytes")
	}
	return &s, nil
}

type Scalar struct {
	traits.PrimeFieldElementTrait[*edwards25519Impl.Fq, edwards25519Impl.Fq, *Scalar, Scalar]
}

func NewScalar(v uint64) *Scalar {
	var s Scalar
	s.V.SetUint64(v)
	return &s
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
