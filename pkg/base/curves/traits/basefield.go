package traits

import (
	"encoding/binary"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/fields"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"hash/fnv"
	"io"
)

type BaseFieldTraitInheriter[FP fields.FiniteFieldElement[FP]] interface {
	Fp() FP
}

type BaseFieldTraitInheriterPtrConstraint[FP fields.FiniteFieldElement[FP], WT any] interface {
	*WT
	BaseFieldTraitInheriter[FP]
}

type BaseField[FP fields.FiniteFieldElement[FP], W BaseFieldTraitInheriterPtrConstraint[FP, WT], WT any] struct {
	_ ds.Incomparable
}

func (f *BaseField[FP, W, WT]) One() W {
	var one WT
	W(&one).Fp().SetOne()
	return &one
}

func (f *BaseField[FP, W, WT]) Zero() W {
	var one WT
	W(&one).Fp().SetZero()
	return &one
}

func (f *BaseField[FP, W, WT]) Random(prng io.Reader) (W, error) {
	var element WT
	if ok := W(&element).Fp().SetRandom(prng); ok == 0 {
		return nil, errs.NewRandomSample("cannot sample field element")
	}

	return &element, nil
}

func (f *BaseField[FP, W, WT]) OpIdentity() W {
	return f.Zero()
}

func (f *BaseField[FP, W, WT]) SubFieldIdentity(i uint) (any, error) {
	//TODO implement me
	panic("implement me")
}

type BaseFieldElement[FP fields.FiniteFieldElementPtrConstraint[FP, T], T any, W BaseFieldTraitInheriterPtrConstraint[FP, WT], WT any] struct {
	V T
}

func (fp *BaseFieldElement[FP, T, W, WT]) Clone() W {
	var clone WT
	W(&clone).Fp().Set(&fp.V)
	return &clone
}

func (fp *BaseFieldElement[FP, T, W, WT]) Equal(rhs W) bool {
	return FP(&fp.V).Equals(rhs.Fp()) == 1
}

func (fp *BaseFieldElement[FP, T, W, WT]) HashCode() uint64 {
	h := fnv.New64a()
	for _, bs := range FP(&fp.V).ComponentsBytes() {
		_, _ = h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(bs))))
		_, _ = h.Write(bs)
	}

	return h.Sum64()
}

func (fp *BaseFieldElement[FP, T, W, WT]) Add(e W) W {
	var sum WT
	W(&sum).Fp().Add(&fp.V, e.Fp())

	return &sum
}

func (fp *BaseFieldElement[FP, T, W, WT]) Double() W {
	var sum WT
	W(&sum).Fp().Add(&fp.V, &fp.V)

	return &sum
}

func (fp *BaseFieldElement[FP, T, W, WT]) Mul(e W) W {
	var prod WT
	W(&prod).Fp().Mul(&fp.V, e.Fp())

	return &prod
}

func (fp *BaseFieldElement[FP, T, W, WT]) Square() W {
	var prod WT
	W(&prod).Fp().Square(&fp.V)

	return &prod
}

func (fp *BaseFieldElement[FP, T, W, WT]) IsOne() bool {
	return FP(&fp.V).IsOne() == 1
}

func (fp *BaseFieldElement[FP, T, W, WT]) TryInv() (W, error) {
	var inv WT
	if ok := W(&inv).Fp().Inv(&fp.V); ok == 0 {
		return nil, errs.NewFailed("division by zero")
	}

	return &inv, nil
}

func (fp *BaseFieldElement[FP, T, W, WT]) TryDiv(e W) (W, error) {
	var q WT
	if ok := W(&q).Fp().Div(&fp.V, e.Fp()); ok == 0 {
		return nil, errs.NewFailed("division by zero")
	}

	return &q, nil
}

func (fp *BaseFieldElement[FP, T, W, WT]) IsZero() bool {
	return FP(&fp.V).IsOne() == 1
}

func (fp *BaseFieldElement[FP, T, W, WT]) Neg() W {
	var neg WT
	W(&neg).Fp().Neg(&fp.V)
	return &neg
}

func (fp *BaseFieldElement[FP, T, W, WT]) Sub(e W) W {
	var diff WT
	W(&diff).Fp().Sub(&fp.V, e.Fp())

	return &diff
}

func (fp *BaseFieldElement[FP, T, W, WT]) EuclideanDiv(rhs W) (quot, rem W, err error) {
	q, err := fp.TryDiv(rhs)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "division by zero")
	}
	var r WT
	W(&r).Fp().SetZero()

	return q, &r, nil
}

func (fp *BaseFieldElement[FP, T, W, WT]) Op(e W) W {
	return fp.Add(e)
}

func (fp *BaseFieldElement[FP, T, W, WT]) OtherOp(e W) W {
	return fp.Mul(e)
}

func (fp *BaseFieldElement[FP, T, W, WT]) OpInv() W {
	return fp.Neg()
}

func (fp *BaseFieldElement[FP, T, W, WT]) IsOpIdentity() bool {
	return fp.IsZero()
}

func (fp *BaseFieldElement[FP, T, W, WT]) TryNeg() (W, error) {
	return fp.Neg(), nil
}

func (fp *BaseFieldElement[FP, T, W, WT]) TrySub(me W) (W, error) {
	return fp.Sub(me), nil
}

func (fp *BaseFieldElement[FP, T, W, WT]) TryOpInv() (W, error) {
	return fp.Neg(), nil
}

func (fp *BaseFieldElement[FP, T, W, WT]) IsProbablyPrime() bool {
	//TODO implement me
	panic("implement me")
}
