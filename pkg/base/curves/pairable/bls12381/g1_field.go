package bls12381

import (
	"encoding"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	h2c "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/errs-go/errs"
)

const (
	// BaseFieldNameG1 is the G1 base field name.
	BaseFieldNameG1 = "BLS12381Fp"
)

var (
	_ algebra.PrimeField[*BaseFieldElementG1]        = (*BaseFieldG1)(nil)
	_ algebra.PrimeFieldElement[*BaseFieldElementG1] = (*BaseFieldElementG1)(nil)
	_ encoding.BinaryMarshaler                       = (*BaseFieldElementG1)(nil)
	_ encoding.BinaryUnmarshaler                     = (*BaseFieldElementG1)(nil)

	baseFieldInstanceG1 *BaseFieldG1
	baseFieldInitOnceG1 sync.Once
	baseFieldOrderG1    *numct.Modulus
)

// BaseFieldG1 represents the base field for G1.
type BaseFieldG1 struct {
	traits.PrimeFieldTrait[*bls12381Impl.Fp, *BaseFieldElementG1, BaseFieldElementG1]
}

// NewG1BaseField returns a new instance.
func NewG1BaseField() *BaseFieldG1 {
	baseFieldInitOnceG1.Do(func() {
		baseFieldOrderG1, _ = numct.NewModulusFromBytesBE(sliceutils.Reversed(bls12381Impl.FpModulus[:]))
		//nolint:exhaustruct // no need for a trait
		baseFieldInstanceG1 = &BaseFieldG1{}
	})

	return baseFieldInstanceG1
}

// Name returns the name of the structure.
func (*BaseFieldG1) Name() string {
	return BaseFieldNameG1
}

// Order returns the group or field order.
func (*BaseFieldG1) Order() cardinal.Cardinal {
	return cardinal.NewFromNumeric(baseFieldOrderG1.Nat())
}

// Characteristic returns the field characteristic.
func (*BaseFieldG1) Characteristic() cardinal.Cardinal {
	return cardinal.NewFromNumeric(baseFieldOrderG1.Nat())
}

// Hash maps input bytes to an element or point.
func (*BaseFieldG1) Hash(bytes []byte) (*BaseFieldElementG1, error) {
	var e [1]bls12381Impl.Fp
	h2c.HashToField(e[:], bls12381Impl.G1CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveSuiteG1, bytes)

	var s BaseFieldElementG1
	s.V.Set(&e[0])
	return &s, nil
}

// ElementSize returns the element size in bytes.
func (*BaseFieldG1) ElementSize() int {
	return bls12381Impl.FpBytes
}

// WideElementSize returns the wide element size in bytes.
func (*BaseFieldG1) WideElementSize() int {
	return bls12381Impl.FpWideBytes
}

// BitLen returns the field modulus bit length.
func (*BaseFieldG1) BitLen() int {
	return bls12381Impl.FpBits
}

// FromBytesBEReduce reduces a big-endian integer into the field.
func (f *BaseFieldG1) FromBytesBEReduce(input []byte) (*BaseFieldElementG1, error) {
	var v numct.Nat
	var nNat numct.Nat
	nNat.SetBytes(input)
	baseFieldOrderG1.Mod(&v, &nNat)
	vBytes := v.Bytes()
	out, err := f.FromBytesBE(vBytes)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to convert reduced bytes into field element")
	}
	return out, nil
}

// BaseFieldElementG1 represents an element of the G1 base field.
type BaseFieldElementG1 struct {
	traits.PrimeFieldElementTrait[*bls12381Impl.Fp, bls12381Impl.Fp, *BaseFieldElementG1, BaseFieldElementG1]
}

// Structure returns the algebraic structure for the receiver.
func (*BaseFieldElementG1) Structure() algebra.Structure[*BaseFieldElementG1] {
	return NewG1BaseField()
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (fe *BaseFieldElementG1) MarshalBinary() (data []byte, err error) {
	return fe.V.Bytes(), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (fe *BaseFieldElementG1) UnmarshalBinary(data []byte) error {
	if ok := fe.V.SetBytes(data); ok == 0 {
		return curves.ErrSerialisation.WithMessage("failed to unmarshal field element")
	}

	return nil
}
