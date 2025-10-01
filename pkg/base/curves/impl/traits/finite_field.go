package traits

import (
	"encoding/binary"
	"hash/fnv"
	"io"
	"iter"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

type FiniteFieldElementWrapper[FP fieldsImpl.FiniteFieldElement[FP]] interface {
	Fp() FP
}

type FiniteFieldElementWrapperPtrConstraint[FP fieldsImpl.FiniteFieldElement[FP], W any] interface {
	*W
	FiniteFieldElementWrapper[FP]
}

type FiniteFieldTrait[FP fieldsImpl.FiniteFieldElement[FP], WP FiniteFieldElementWrapperPtrConstraint[FP, W], W any] struct{}

func (f *FiniteFieldTrait[FP, WP, W]) FromComponentsBytes(data [][]byte) (WP, error) {
	leData := make([][]byte, len(data))
	for i, d := range data {
		leData[i] = sliceutils.Reversed(d)
	}
	var e W
	if ok := WP(&e).Fp().SetUniformBytes(leData...); ok == 0 {
		return nil, errs.NewFailed("cannot set byte")
	}
	return &e, nil
}

func (f *FiniteFieldTrait[FP, WP, W]) Random(prng io.Reader) (WP, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng")
	}
	var rand W
	if ok := WP(&rand).Fp().SetRandom(prng); ok == 0 {
		return nil, errs.NewRandomSample("cannot sample field element")
	}
	return &rand, nil
}

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

func (f *FiniteFieldTrait[FP, WP, W]) One() WP {
	var one W
	WP(&one).Fp().SetOne()
	return &one
}

func (f *FiniteFieldTrait[FP, WP, W]) Zero() WP {
	var zero W
	WP(&zero).Fp().SetZero()
	return &zero
}

func (f *FiniteFieldTrait[FP, WP, W]) OpIdentity() WP {
	return f.Zero()
}

type FiniteFieldElementTrait[FP fieldsImpl.FiniteFieldElementPtr[FP, F], F any, WP FiniteFieldElementWrapperPtrConstraint[FP, W], W any] struct {
	V F
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) Fp() FP {
	return &fe.V
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) Clone() WP {
	var clone W
	WP(&clone).Fp()
	return &clone
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) Add(e WP) WP {
	var sum W
	WP(&sum).Fp().Add(&fe.V, e.Fp())
	return &sum
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) Double() WP {
	return fe.Add(fe.Clone())
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) Sub(e WP) WP {
	var diff W
	WP(&diff).Fp().Sub(&fe.V, e.Fp())
	return &diff
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) Neg() WP {
	var neg W
	WP(&neg).Fp().Neg(&fe.V)
	return &neg
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) Mul(e WP) WP {
	var prod W
	WP(&prod).Fp().Mul(&fe.V, e.Fp())
	return &prod
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) Square() WP {
	var square W
	WP(&square).Fp().Square(&fe.V)
	return &square
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) TryInv() (WP, error) {
	var inv W
	if ok := WP(&inv).Fp().Inv(&fe.V); ok == 0 {
		return nil, errs.NewFailed("division by zero")
	}
	return &inv, nil
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) TryDiv(e WP) (WP, error) {
	var q W
	if ok := WP(&q).Fp().Div(&fe.V, e.Fp()); ok == 0 {
		return nil, errs.NewFailed("division by zero")
	}
	return &q, nil
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) EuclideanDiv(rhs WP) (quot, rem WP, err error) {
	q, err := fe.TryDiv(rhs)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "division by zero")
	}
	var r W
	WP(&r).Fp().SetZero()
	return q, &r, nil
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) Equal(rhs WP) bool {
	return FP(&fe.V).Equal(rhs.Fp()) != 0
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) HashCode() base.HashCode {
	h := fnv.New64a()
	for _, bs := range FP(&fe.V).ComponentsBytes() {
		_, _ = h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(bs))))
		_, _ = h.Write(bs)
	}

	return base.HashCode(h.Sum64())
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) IsOne() bool {
	return FP(&fe.V).IsOne() != 0
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) IsZero() bool {
	return FP(&fe.V).IsOne() != 0
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) Bytes() []byte {
	return slices.Concat(fe.ComponentsBytes()...)
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) ComponentsBytes() [][]byte {
	leData := FP(&fe.V).ComponentsBytes()
	beData := make([][]byte, len(leData))
	for i, d := range leData {
		beData[i] = sliceutils.Reverse(d)
	}
	return beData
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) Op(e WP) WP {
	return fe.Add(e)
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) OtherOp(e WP) WP {
	return fe.Mul(e)
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) IsOpIdentity() bool {
	return fe.IsZero()
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) TryOpInv() (WP, error) {
	return fe.Neg(), nil
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) TryNeg() (WP, error) {
	return fe.Neg(), nil
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) TrySub(me WP) (WP, error) {
	return fe.Sub(me), nil
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) OpInv() WP {
	return fe.Neg()
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) EuclideanValuation() WP {
	var out W
	var zero W
	var one W
	WP(&out).Fp().Set(&fe.V)
	WP(&zero).Fp().SetZero()
	WP(&one).Fp().SetOne()
	WP(&out).Fp().CondAssign(fe.Fp().IsZero(), WP(&zero).Fp(), WP(&one).Fp())
	return &out
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) IsProbablyPrime() bool {
	//TODO implement me
	panic("implement me")
}

func (fe *FiniteFieldElementTrait[FP, F, WP, W]) String() string {
	//TODO implement me
	panic("implement me")
}
