package traits

import (
	"hash/fnv"
	"io"
	"iter"
	"math/big"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base"
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

type PrimeFieldElementWrapper[FP fieldsImpl.PrimeFieldElement[FP]] interface {
	Fp() FP
}

type PrimeFieldElementWrapperPtrConstraint[FP fieldsImpl.PrimeFieldElement[FP], W any] interface {
	*W
	PrimeFieldElementWrapper[FP]
}

type PrimeFieldTrait[FP fieldsImpl.PrimeFieldElement[FP], WP PrimeFieldElementWrapperPtrConstraint[FP, W], W any] struct{}

func (f *PrimeFieldTrait[FP, WP, W]) IsSemiDomain() bool {
	return true
}

func (f *PrimeFieldTrait[FP, WP, W]) FromBytes(bytes []byte) (WP, error) {
	leBytes := sliceutils.Reversed(bytes)
	var e W
	if ok := WP(&e).Fp().SetBytes(leBytes); ok == 0 {
		return nil, errs.NewFailed("cannot set bytes")
	}
	return &e, nil
}

func (f *PrimeFieldTrait[FP, WP, W]) FromBytesBE(input []byte) (WP, error) {
	return f.FromBytes(input)
}

func (f *PrimeFieldTrait[FP, WP, W]) FromWideBytes(bytes []byte) (WP, error) {
	leBytes := sliceutils.Reversed(bytes)
	var e W
	if ok := WP(&e).Fp().SetBytesWide(leBytes); ok == 0 {
		return nil, errs.NewFailed("cannot set bytes")
	}
	return &e, nil
}

func (f *PrimeFieldTrait[FP, WP, W]) FromComponentsBytes(data [][]byte) (WP, error) {
	leData := make([][]byte, len(data))
	for i, d := range data {
		leData[i] = sliceutils.Reversed(d)
	}
	var e W
	if ok := WP(&e).Fp().SetUniformBytes(leData...); ok == 0 {
		return nil, errs.NewFailed("cannot set uniform bytes")
	}
	return &e, nil
}

func (f *PrimeFieldTrait[FP, WP, W]) FromUint64(v uint64) WP {
	var e W
	WP(&e).Fp().SetUint64(v)
	return &e
}

func (f *PrimeFieldTrait[FP, WP, W]) FromCardinal(card cardinal.Cardinal) (WP, error) {
	leData := sliceutils.Reverse(card.Bytes())
	var e W
	if ok := WP(&e).Fp().SetBytesWide(leData); ok == 0 {
		return nil, errs.NewFailed("cannot set wide bytes")
	}
	return &e, nil
}

func (f *PrimeFieldTrait[FP, WP, W]) One() WP {
	var one W
	WP(&one).Fp().SetOne()
	return &one
}

func (f *PrimeFieldTrait[FP, WP, W]) Zero() WP {
	var zero W
	WP(&zero).Fp().SetZero()
	return &zero
}

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

func (f *PrimeFieldTrait[FP, WP, W]) Random(prng io.Reader) (WP, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng")
	}
	var rand W
	if ok := WP(&rand).Fp().SetRandom(prng); ok == 0 {
		return nil, errs.NewRandomSample("cannot sample prime field element")
	}
	return &rand, nil
}

func (f *PrimeFieldTrait[FP, WP, W]) ExtensionDegree() uint {
	return 1
}

func (f *PrimeFieldTrait[FP, WP, W]) PartialCompare(x, y WP) base.PartialOrdering {
	return base.PartialOrdering(f.Compare(x, y))
}

func (f *PrimeFieldTrait[FP, WP, W]) Compare(x, y WP) base.Ordering {
	out := base.ParseOrderingFromMasks(fieldsImpl.SliceCmpLE(x.Fp().Limbs(), y.Fp().Limbs()))
	if out.IsIncomparable() {
		panic("prime field elements cannot be incomparable")
	}
	return base.Ordering(out)
}

func (f *PrimeFieldTrait[FP, WP, W]) OpIdentity() WP {
	return f.Zero()
}

func (f *PrimeFieldTrait[FP, WP, W]) SubFieldIdentity(i uint) (any, error) {
	//TODO implement me
	panic("implement me")
}

type PrimeFieldElementTrait[FP fieldsImpl.PrimeFieldElementPtr[FP, F], F any, WP PrimeFieldElementWrapperPtrConstraint[FP, W], W any] struct {
	V F
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) Fp() FP {
	return &fe.V
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) Clone() WP {
	var clone W
	WP(&clone).Fp().Set(&fe.V)
	return &clone
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) Add(e WP) WP {
	var sum W
	WP(&sum).Fp().Add(&fe.V, e.Fp())
	return &sum
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) Double() WP {
	return fe.Add(fe.Clone())
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) Sub(e WP) WP {
	var diff W
	WP(&diff).Fp().Sub(&fe.V, e.Fp())
	return &diff
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) Neg() WP {
	var neg W
	WP(&neg).Fp().Neg(&fe.V)
	return &neg
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) Mul(e WP) WP {
	var prod W
	WP(&prod).Fp().Mul(&fe.V, e.Fp())
	return &prod
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) Square() WP {
	var square W
	WP(&square).Fp().Square(&fe.V)
	return &square
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) TryInv() (WP, error) {
	var inv W
	if ok := WP(&inv).Fp().Inv(&fe.V); ok == 0 {
		return nil, errs.NewFailed("division by zero")
	}
	return &inv, nil
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) TryDiv(e WP) (WP, error) {
	var quot W
	if ok := WP(&quot).Fp().Div(&fe.V, e.Fp()); ok == 0 {
		return nil, errs.NewFailed("division by zero")
	}
	return &quot, nil
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) EuclideanDiv(rhs WP) (quot, rem WP, err error) {
	quot, err = fe.TryDiv(rhs)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "division by zero")
	}

	var r W
	WP(&r).Fp().SetZero()
	return quot, &r, nil
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) IsZero() bool {
	return FP(&fe.V).IsZero() != 0
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) IsOne() bool {
	return FP(&fe.V).IsOne() != 0
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) Equal(rhs WP) bool {
	return FP(&fe.V).Equal(rhs.Fp()) != 0
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) IsLessThanOrEqual(rhs WP) bool {
	out := base.ParseOrderingFromMasks(fieldsImpl.SliceCmpLE(FP(&fe.V).Limbs(), rhs.Fp().Limbs()))
	if out == base.Incomparable {
		panic("prime field elements cannot be incomparable")
	}
	return out.IsLessThan() || out.IsEqual()
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) IsOdd() bool {
	return fieldsImpl.IsOdd[FP](&fe.V) != 0
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) IsEven() bool {
	return !fe.IsOdd()
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) IsNegative() bool {
	return fieldsImpl.IsNegative[FP](&fe.V) != 0
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) IsPositive() bool {
	return !fe.IsNegative()
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) HashCode() base.HashCode {
	h := fnv.New64a()
	_, _ = h.Write(FP(&fe.V).Bytes())
	return base.HashCode(h.Sum64())
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) Bytes() []byte {
	return sliceutils.Reverse(FP(&fe.V).Bytes())
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) BytesBE() []byte {
	return sliceutils.Reverse(FP(&fe.V).Bytes())
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) ComponentsBytes() [][]byte {
	// TODO: fix
	leBytes := fe.ComponentsBytes()
	beBytes := make([][]byte, len(leBytes))
	for i, b := range leBytes {
		beBytes[i] = sliceutils.Reverse(b)
	}
	return beBytes
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) Cardinal() cardinal.Cardinal {
	data := sliceutils.Reverse(FP(&fe.V).Bytes())
	nat := new(saferith.Nat).SetBytes(data)
	return cardinal.NewFromSaferith(nat)
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) Op(e WP) WP {
	return fe.Add(e)
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) OtherOp(e WP) WP {
	return fe.Mul(e)
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) TrySub(me WP) (WP, error) {
	return fe.Sub(me), nil
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) OpInv() WP {
	return fe.Neg()
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) TryNeg() (WP, error) {
	return fe.Neg(), nil
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) IsProbablyPrime() bool {
	return new(big.Int).SetBytes(fe.Bytes()).ProbablyPrime(0)
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) IsOpIdentity() bool {
	return fe.IsZero()
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) TryOpInv() (WP, error) {
	return fe.Neg(), nil
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) EuclideanValuation() cardinal.Cardinal {
	if fe.IsZero() {
		return cardinal.Zero()
	} else {
		return cardinal.New(1)
	}
}

func (fe *PrimeFieldElementTrait[FP, F, WP, W]) String() string {
	data := sliceutils.Reverse(FP(&fe.V).Bytes())
	return new(big.Int).SetBytes(data).String()
}
