package traits

import (
	"hash/fnv"
	"io"
	"iter"
	"math/big"

	"github.com/bronlabs/bron-crypto/pkg/base"
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

// PrimeFieldElementWrapper exposes the underlying prime field element.
type PrimeFieldElementWrapper[FP fieldsImpl.PrimeFieldElement[FP]] interface {
	// Fp defines the Fp operation.
	Fp() FP
}

// PrimeFieldElementWrapperPtrConstraint restricts wrappers to pointer receivers.
type PrimeFieldElementWrapperPtrConstraint[FP fieldsImpl.PrimeFieldElement[FP], W any] interface {
	*W
	PrimeFieldElementWrapper[FP]
}

// PrimeFieldTrait provides constructors and helpers for prime fields.
type PrimeFieldTrait[FP fieldsImpl.PrimeFieldElement[FP], WP PrimeFieldElementWrapperPtrConstraint[FP, W], W any] struct{}

// IsDomain reports whether the field forms an integral domain.
func (*PrimeFieldTrait[FP, WP, W]) IsDomain() bool {
	return true
}

// FromBytes builds an element from big-endian bytes.
func (*PrimeFieldTrait[FP, WP, W]) FromBytes(bytes []byte) (WP, error) {
	leBytes := sliceutils.Reversed(bytes)
	var e W
	if ok := WP(&e).Fp().SetBytes(leBytes); ok == 0 {
		return nil, curves.ErrFailed.WithMessage("cannot set bytes")
	}
	return &e, nil
}

// FromBytesBE builds an element from big-endian bytes.
func (f *PrimeFieldTrait[FP, WP, W]) FromBytesBE(input []byte) (WP, error) {
	return f.FromBytes(input)
}

// FromWideBytes builds an element from wide big-endian bytes.
func (*PrimeFieldTrait[FP, WP, W]) FromWideBytes(bytes []byte) (WP, error) {
	leBytes := sliceutils.Reversed(bytes)
	var e W
	if ok := WP(&e).Fp().SetBytesWide(leBytes); ok == 0 {
		return nil, curves.ErrFailed.WithMessage("cannot set bytes")
	}
	return &e, nil
}

// FromComponentsBytes builds an element from big-endian component byte slices.
func (*PrimeFieldTrait[FP, WP, W]) FromComponentsBytes(data [][]byte) (WP, error) {
	leData := make([][]byte, len(data))
	for i, d := range data {
		leData[i] = sliceutils.Reversed(d)
	}
	var e W
	if ok := WP(&e).Fp().SetUniformBytes(leData...); ok == 0 {
		return nil, curves.ErrFailed.WithMessage("cannot set uniform bytes")
	}
	return &e, nil
}

// FromUint64 builds an element from a uint64 value.
func (*PrimeFieldTrait[FP, WP, W]) FromUint64(v uint64) WP {
	var e W
	WP(&e).Fp().SetUint64(v)
	return &e
}

// FromCardinal builds an element from a cardinal value.
func (*PrimeFieldTrait[FP, WP, W]) FromCardinal(card cardinal.Cardinal) (WP, error) {
	leData := sliceutils.Reverse(card.Bytes())
	var e W
	if ok := WP(&e).Fp().SetBytesWide(leData); ok == 0 {
		return nil, curves.ErrFailed.WithMessage("cannot set wide bytes")
	}
	return &e, nil
}

// One returns the multiplicative identity.
func (*PrimeFieldTrait[FP, WP, W]) One() WP {
	var one W
	WP(&one).Fp().SetOne()
	return &one
}

// Zero returns the additive identity.
func (*PrimeFieldTrait[FP, WP, W]) Zero() WP {
	var zero W
	WP(&zero).Fp().SetZero()
	return &zero
}

// Iter returns an iterator over field elements starting at one.
func (f *PrimeFieldTrait[FP, WP, W]) Iter() iter.Seq[WP] {
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

// Random samples a field element using the provided PRNG.
func (*PrimeFieldTrait[FP, WP, W]) Random(prng io.Reader) (WP, error) {
	if prng == nil {
		return nil, curves.ErrNil.WithMessage("prng")
	}
	var rand W
	if ok := WP(&rand).Fp().SetRandom(prng); ok == 0 {
		return nil, curves.ErrRandomSample.WithMessage("cannot sample prime field element")
	}
	return &rand, nil
}

// ExtensionDegree returns the degree of the prime field extension.
func (*PrimeFieldTrait[FP, WP, W]) ExtensionDegree() uint {
	return 1
}

// PartialCompare returns a partial ordering for x and y.
func (f *PrimeFieldTrait[FP, WP, W]) PartialCompare(x, y WP) base.PartialOrdering {
	return base.PartialOrdering(f.Compare(x, y))
}

// Compare returns an ordering for x and y.
func (*PrimeFieldTrait[FP, WP, W]) Compare(x, y WP) base.Ordering {
	out := base.ParseOrderingFromMasks(fieldsImpl.SliceCmpLE(x.Fp().Limbs(), y.Fp().Limbs()))
	if out.IsIncomparable() {
		panic("prime field elements cannot be incomparable")
	}
	return base.Ordering(out)
}

// OpIdentity returns the additive identity for the group operation.
func (f *PrimeFieldTrait[FP, WP, W]) OpIdentity() WP {
	return f.Zero()
}

// PrimeFieldElementTrait implements common arithmetic operations for elements.
type PrimeFieldElementTrait[FP fieldsImpl.PrimeFieldElementPtr[FP, F], F any, WP PrimeFieldElementWrapperPtrConstraint[FP, W], W any] struct {
	V F
}

// Fp returns the underlying field element pointer.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) Fp() FP {
	return &fe.V
}

// Clone returns a new element with the same value.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) Clone() WP {
	var clone W
	WP(&clone).Fp().Set(&fe.V)
	return &clone
}

// Add returns the sum of this element and e.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) Add(e WP) WP {
	var sum W
	WP(&sum).Fp().Add(&fe.V, e.Fp())
	return &sum
}

// Double returns the element multiplied by two.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) Double() WP {
	return fe.Add(fe.Clone())
}

// Sub returns the difference of this element and e.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) Sub(e WP) WP {
	var diff W
	WP(&diff).Fp().Sub(&fe.V, e.Fp())
	return &diff
}

// Neg returns the additive inverse of this element.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) Neg() WP {
	var neg W
	WP(&neg).Fp().Neg(&fe.V)
	return &neg
}

// Mul returns the product of this element and e.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) Mul(e WP) WP {
	var prod W
	WP(&prod).Fp().Mul(&fe.V, e.Fp())
	return &prod
}

// Square returns the square of this element.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) Square() WP {
	var square W
	WP(&square).Fp().Square(&fe.V)
	return &square
}

// TryInv computes the multiplicative inverse, or returns an error on zero.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) TryInv() (WP, error) {
	var inv W
	if ok := WP(&inv).Fp().Inv(&fe.V); ok == 0 {
		return nil, curves.ErrFailed.WithMessage("division by zero")
	}
	return &inv, nil
}

// TryDiv divides this element by e, or returns an error on zero divisor.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) TryDiv(e WP) (WP, error) {
	var quot W
	if ok := WP(&quot).Fp().Div(&fe.V, e.Fp()); ok == 0 {
		return nil, curves.ErrFailed.WithMessage("division by zero")
	}
	return &quot, nil
}

// EuclideanDiv returns the quotient and zero remainder for field division.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) EuclideanDiv(rhs WP) (quot, rem WP, err error) {
	quot, err = fe.TryDiv(rhs)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("division by zero")
	}

	var r W
	WP(&r).Fp().SetZero()
	return quot, &r, nil
}

// IsZero reports whether the element is zero.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) IsZero() bool {
	return FP(&fe.V).IsZero() != 0
}

// IsOne reports whether the element is one.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) IsOne() bool {
	return FP(&fe.V).IsOne() != 0
}

// Equal reports whether this element equals rhs.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) Equal(rhs WP) bool {
	return FP(&fe.V).Equal(rhs.Fp()) != 0
}

// IsLessThanOrEqual reports whether this element is <= rhs.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) IsLessThanOrEqual(rhs WP) bool {
	out := base.ParseOrderingFromMasks(fieldsImpl.SliceCmpLE(FP(&fe.V).Limbs(), rhs.Fp().Limbs()))
	if out == base.Incomparable {
		panic("prime field elements cannot be incomparable")
	}
	return out.IsLessThan() || out.IsEqual()
}

// IsOdd reports whether the element is odd.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) IsOdd() bool {
	return fieldsImpl.IsOdd[FP](&fe.V) != 0
}

// IsEven reports whether the element is even.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) IsEven() bool {
	return !fe.IsOdd()
}

// IsNegative reports whether the element is negative in the field's ordering.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) IsNegative() bool {
	return fieldsImpl.IsNegative[FP](&fe.V) != 0
}

// IsPositive reports whether the element is non-negative in the field's ordering.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) IsPositive() bool {
	return !fe.IsNegative()
}

// HashCode returns a stable hash of the element bytes.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) HashCode() base.HashCode {
	h := fnv.New64a()
	_, _ = h.Write(FP(&fe.V).Bytes())
	return base.HashCode(h.Sum64())
}

// Bytes returns the big-endian byte encoding.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) Bytes() []byte {
	return sliceutils.Reverse(FP(&fe.V).Bytes())
}

// BytesBE returns the big-endian byte encoding.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) BytesBE() []byte {
	return sliceutils.Reverse(FP(&fe.V).Bytes())
}

// ComponentsBytes returns big-endian component byte slices.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) ComponentsBytes() [][]byte {
	beBytes := make([][]byte, 1) // not a field extension
	beBytes[0] = fe.BytesBE()
	return beBytes
}

// Cardinal converts the element to a cardinal value.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) Cardinal() cardinal.Cardinal {
	data := sliceutils.Reverse(FP(&fe.V).Bytes())
	var nat numct.Nat
	nat.SetBytes(data)
	return cardinal.NewFromNumeric(&nat)
}

// Op returns the group operation result (addition).
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) Op(e WP) WP {
	return fe.Add(e)
}

// OtherOp returns the secondary operation result (multiplication).
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) OtherOp(e WP) WP {
	return fe.Mul(e)
}

// TrySub returns the difference between this element and me.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) TrySub(me WP) (WP, error) {
	return fe.Sub(me), nil
}

// OpInv returns the additive inverse for the group operation.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) OpInv() WP {
	return fe.Neg()
}

// TryNeg returns the additive inverse.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) TryNeg() (WP, error) {
	return fe.Neg(), nil
}

// IsProbablyPrime reports whether the element interpreted as an integer is probably prime.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) IsProbablyPrime() bool {
	return new(big.Int).SetBytes(fe.Bytes()).ProbablyPrime(0)
}

// IsOpIdentity reports whether the element is the additive identity.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) IsOpIdentity() bool {
	return fe.IsZero()
}

// TryOpInv returns the additive inverse for the group operation.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) TryOpInv() (WP, error) {
	return fe.Neg(), nil
}

// EuclideanValuation returns 0 for zero and 1 otherwise.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) EuclideanValuation() cardinal.Cardinal {
	if fe.IsZero() {
		return cardinal.Zero()
	} else {
		return cardinal.New(1)
	}
}

// String returns the base-10 integer representation of the element.
func (fe *PrimeFieldElementTrait[FP, F, WP, W]) String() string {
	data := sliceutils.Reverse(FP(&fe.V).Bytes())
	return new(big.Int).SetBytes(data).String()
}
