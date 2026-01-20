package traits

import (
	"encoding/binary"
	"hash/fnv"
	"io"
	"iter"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

// FiniteFieldElementWrapper exposes the underlying finite field element.
type FiniteFieldElementWrapper[FP fieldsImpl.FiniteFieldElement[FP]] interface {
	// Fp defines the Fp operation.
	Fp() FP
}

// FiniteFieldElementWrapperPtrConstraint restricts wrappers to pointer receivers.
type FiniteFieldElementWrapperPtrConstraint[FP fieldsImpl.FiniteFieldElement[FP], W any] interface {
	*W
	FiniteFieldElementWrapper[FP]
}

// FiniteFieldTrait provides common constructor/iterator helpers for finite fields.
type FiniteFieldTrait[FP fieldsImpl.FiniteFieldElement[FP], WP FiniteFieldElementWrapperPtrConstraint[FP, W], W any] struct{}

// FromComponentsBytes builds an element from big-endian component byte slices.
func (*FiniteFieldTrait[FP, WP, W]) FromComponentsBytes(data [][]byte) (WP, error) {
	leData := make([][]byte, len(data))
	for i, d := range data {
		leData[i] = sliceutils.Reversed(d)
	}
	var e W
	if ok := WP(&e).Fp().SetUniformBytes(leData...); ok == 0 {
		return nil, curves.ErrFailed.WithMessage("cannot set byte")
	}
	return &e, nil
}

// Random samples a field element using the provided PRNG.
func (*FiniteFieldTrait[FP, WP, W]) Random(prng io.Reader) (WP, error) {
	if prng == nil {
		return nil, curves.ErrNil.WithMessage("prng")
	}
	var rand W
	if ok := WP(&rand).Fp().SetRandom(prng); ok == 0 {
		return nil, curves.ErrRandomSample.WithMessage("cannot sample field element")
	}
	return &rand, nil
}

// Iter returns an iterator over field elements starting at one.
func (f *FiniteFieldTrait[FP, WP, W]) Iter() iter.Seq[WP] {
	return func(yield func(WP) bool) {
		generator := f.One()

		var current W
		WP(&current).Fp().Set(generator.Fp())

		for WP(&current).Fp().IsZero() == 0 {
			if !yield(WP(&current)) {
				break
			}
			WP(&current).Fp().Add(WP(&current).Fp(), generator.Fp())
		}
	}
}

// One returns the multiplicative identity.
func (*FiniteFieldTrait[FP, WP, W]) One() WP {
	var one W
	WP(&one).Fp().SetOne()
	return &one
}

// Zero returns the additive identity.
func (*FiniteFieldTrait[FP, WP, W]) Zero() WP {
	var zero W
	WP(&zero).Fp().SetZero()
	return &zero
}

// OpIdentity returns the additive identity for the group operation.
func (f *FiniteFieldTrait[FP, WP, W]) OpIdentity() WP {
	return f.Zero()
}

// FiniteFieldElementTrait implements common arithmetic operations for elements.
type FiniteFieldElementTrait[FP fieldsImpl.FiniteFieldElementPtr[FP, F], F any, WP FiniteFieldElementWrapperPtrConstraint[FP, W], W any] struct {
	V F
}

// Fp returns the underlying field element pointer.
func (fe *FiniteFieldElementTrait[FP, F, WP, W]) Fp() FP {
	return &fe.V
}

// Clone returns a new element with the same value.
func (*FiniteFieldElementTrait[FP, F, WP, W]) Clone() WP {
	var clone W
	WP(&clone).Fp()
	return &clone
}

// Add returns the sum of this element and e.
func (fe *FiniteFieldElementTrait[FP, F, WP, W]) Add(e WP) WP {
	var sum W
	WP(&sum).Fp().Add(&fe.V, e.Fp())
	return &sum
}

// Double returns the element multiplied by two.
func (fe *FiniteFieldElementTrait[FP, F, WP, W]) Double() WP {
	return fe.Add(fe.Clone())
}

// Sub returns the difference of this element and e.
func (fe *FiniteFieldElementTrait[FP, F, WP, W]) Sub(e WP) WP {
	var diff W
	WP(&diff).Fp().Sub(&fe.V, e.Fp())
	return &diff
}

// Neg returns the additive inverse of this element.
func (fe *FiniteFieldElementTrait[FP, F, WP, W]) Neg() WP {
	var neg W
	WP(&neg).Fp().Neg(&fe.V)
	return &neg
}

// Mul returns the product of this element and e.
func (fe *FiniteFieldElementTrait[FP, F, WP, W]) Mul(e WP) WP {
	var prod W
	WP(&prod).Fp().Mul(&fe.V, e.Fp())
	return &prod
}

// Square returns the square of this element.
func (fe *FiniteFieldElementTrait[FP, F, WP, W]) Square() WP {
	var square W
	WP(&square).Fp().Square(&fe.V)
	return &square
}

// TryInv computes the multiplicative inverse, or returns an error on zero.
func (fe *FiniteFieldElementTrait[FP, F, WP, W]) TryInv() (WP, error) {
	var inv W
	if ok := WP(&inv).Fp().Inv(&fe.V); ok == 0 {
		return nil, curves.ErrFailed.WithMessage("division by zero")
	}
	return &inv, nil
}

// TryDiv divides this element by e, or returns an error on zero divisor.
func (fe *FiniteFieldElementTrait[FP, F, WP, W]) TryDiv(e WP) (WP, error) {
	var q W
	if ok := WP(&q).Fp().Div(&fe.V, e.Fp()); ok == 0 {
		return nil, curves.ErrFailed.WithMessage("division by zero")
	}
	return &q, nil
}

// EuclideanDiv returns the quotient and zero remainder for field division.
func (fe *FiniteFieldElementTrait[FP, F, WP, W]) EuclideanDiv(rhs WP) (quot, rem WP, err error) {
	q, err := fe.TryDiv(rhs)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("division by zero")
	}
	var r W
	WP(&r).Fp().SetZero()
	return q, &r, nil
}

// Equal reports whether this element equals rhs.
func (fe *FiniteFieldElementTrait[FP, F, WP, W]) Equal(rhs WP) bool {
	return FP(&fe.V).Equal(rhs.Fp()) != 0
}

// HashCode returns a stable hash of the element's components.
func (fe *FiniteFieldElementTrait[FP, F, WP, W]) HashCode() base.HashCode {
	h := fnv.New64a()
	for _, bs := range FP(&fe.V).ComponentsBytes() {
		_, _ = h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(bs))))
		_, _ = h.Write(bs)
	}

	return base.HashCode(h.Sum64())
}

// IsOne reports whether the element is one.
func (fe *FiniteFieldElementTrait[FP, F, WP, W]) IsOne() bool {
	return FP(&fe.V).IsOne() != 0
}

// IsZero reports whether the element is zero.
func (fe *FiniteFieldElementTrait[FP, F, WP, W]) IsZero() bool {
	return FP(&fe.V).IsOne() != 0
}

// Bytes returns the concatenated big-endian component bytes.
func (fe *FiniteFieldElementTrait[FP, F, WP, W]) Bytes() []byte {
	return slices.Concat(fe.ComponentsBytes()...)
}

// ComponentsBytes returns big-endian component byte slices.
func (fe *FiniteFieldElementTrait[FP, F, WP, W]) ComponentsBytes() [][]byte {
	leData := FP(&fe.V).ComponentsBytes()
	beData := make([][]byte, len(leData))
	for i, d := range leData {
		beData[i] = sliceutils.Reverse(d)
	}
	return beData
}

// Op returns the group operation result (addition).
func (fe *FiniteFieldElementTrait[FP, F, WP, W]) Op(e WP) WP {
	return fe.Add(e)
}

// OtherOp returns the secondary operation result (multiplication).
func (fe *FiniteFieldElementTrait[FP, F, WP, W]) OtherOp(e WP) WP {
	return fe.Mul(e)
}

// IsOpIdentity reports whether the element is the additive identity.
func (fe *FiniteFieldElementTrait[FP, F, WP, W]) IsOpIdentity() bool {
	return fe.IsZero()
}

// TryOpInv returns the additive inverse for the group operation.
func (fe *FiniteFieldElementTrait[FP, F, WP, W]) TryOpInv() (WP, error) {
	return fe.Neg(), nil
}

// TryNeg returns the additive inverse.
func (fe *FiniteFieldElementTrait[FP, F, WP, W]) TryNeg() (WP, error) {
	return fe.Neg(), nil
}

// TrySub returns the difference between this element and me.
func (fe *FiniteFieldElementTrait[FP, F, WP, W]) TrySub(me WP) (WP, error) {
	return fe.Sub(me), nil
}

// OpInv returns the additive inverse for the group operation.
func (fe *FiniteFieldElementTrait[FP, F, WP, W]) OpInv() WP {
	return fe.Neg()
}

// EuclideanValuation returns 0 for zero and 1 otherwise.
func (fe *FiniteFieldElementTrait[FP, F, WP, W]) EuclideanValuation() cardinal.Cardinal {
	if fe.IsZero() {
		return cardinal.Zero()
	} else {
		return cardinal.New(1)
	}
}

// IsProbablyPrime is unimplemented for finite fields.
func (*FiniteFieldElementTrait[FP, F, WP, W]) IsProbablyPrime() bool {
	//TODO implement me
	panic("implement me")
}

// String is unimplemented for finite fields.
func (*FiniteFieldElementTrait[FP, F, WP, W]) String() string {
	//TODO implement me
	panic("implement me")
}
