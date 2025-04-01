package traits

import (
	"encoding/binary"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"hash/fnv"
	"math/big"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/fields"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/cronokirby/saferith"
)

type ScalarTraitInheriter[FQ fieldsImpl.PrimeFieldElement[FQ]] interface {
	Fq() FQ
}

type ScalarTraitInheriterPtrConstraint[FQ fieldsImpl.PrimeFieldElement[FQ], WT any] interface {
	*WT
	ScalarTraitInheriter[FQ]
}

type ScalarField[FQ fieldsImpl.PrimeFieldElement[FQ], W ScalarTraitInheriterPtrConstraint[FQ, WT], WT any] struct {
	_ ds.Incomparable
}

func (f *ScalarField[FQ, W, WT]) FromBytes(data []byte) (W, error) {
	var out WT
	if ok := W(&out).Fq().SetBytes(sliceutils.Reversed(data)); ok == 0 {
		return nil, errs.NewFailed("invalid bytes")
	}

	return &out, nil
}

func (f *ScalarField[FQ, W, WT]) FromWideBytes(data []byte) (W, error) {
	var out WT
	if ok := W(&out).Fq().SetBytesWide(sliceutils.Reversed(data)); ok == 0 {
		return nil, errs.NewFailed("invalid bytes")
	}

	return &out, nil
}

func (f *ScalarField[FQ, W, WT]) FromComponentsBytes(data [][]byte) (W, error) {
	leData := make([][]byte, len(data))
	for i, c := range data {
		leData[i] = sliceutils.Reversed(c)
	}

	var e WT
	if ok := W(&e).Fq().SetUniformBytes(leData...); ok == 0 {
		return nil, errs.NewFailed("invalid bytes")
	}

	return &e, nil
}

func (f *ScalarField[FQ, W, WT]) Zero() W {
	var v WT
	W(&v).Fq().SetZero()
	return &v
}

func (f *ScalarField[FQ, W, WT]) One() W {
	var v WT
	W(&v).Fq().SetOne()
	return &v
}

func (f *ScalarField[FQ, W, WT]) Compare(x, y W) algebra.Ordering {
	return algebra.Ordering(ct.SliceCmpLE(x.Fq().Limbs(), y.Fq().Limbs()))
}

func (f *ScalarField[FQ, W, WT]) PartialCompare(x, y W) algebra.PartialOrdering {
	return algebra.PartialOrdering(f.Compare(x, y))
}

func (f *ScalarField[FQ, W, WT]) OpIdentity() W {
	return f.Zero()
}

func (f *ScalarField[FQ, W, WT]) SubFieldIdentity(i uint) (any, error) {
	if i == 1 {
		return f.OpIdentity(), nil
	}
	var out W
	return out, errs.NewValue("invalid subfield index")
}

func NewScalarFromNat[FQ fieldsImpl.PrimeFieldElement[FQ], W ScalarTraitInheriterPtrConstraint[FQ, WT], WT any](input *saferith.Nat, fieldOrder *saferith.Modulus) (W, error) {
	if input == nil || fieldOrder == nil {
		return nil, errs.NewIsNil("argument")
	}
	reducedV := new(saferith.Nat).Mod(input, fieldOrder)
	vBytes := reducedV.Bytes()
	slices.Reverse(vBytes)

	var v WT
	if ok := W(&v).Fq().SetBytes(vBytes); ok == 0 {
		return nil, errs.NewFailed("cannot set scalar")
	}
	return &v, nil
}

type Scalar[FE fieldsImpl.PrimeFieldElementPtrConstraint[FE, T], T any, W ScalarTraitInheriterPtrConstraint[FE, WT], WT any] struct {
	V T
}

func (s *Scalar[_, _, W, WT]) Clone() W {
	var out WT
	W(&out).Fq().Set(&s.V)
	return &out
}

func (s *Scalar[FE, T, W, WT]) Add(x W) W {
	var v WT
	W(&v).Fq().Add(&s.V, x.Fq())
	return &v
}

func (s *Scalar[_, _, W, _]) Double() W {
	return s.Add(s.Clone())
}

func (s *Scalar[FE, T, W, WT]) Sub(x W) W {
	var v WT
	W(&v).Fq().Sub(&s.V, x.Fq())
	return &v
}

func (s *Scalar[FE, T, W, WT]) Neg() W {
	var v WT
	W(&v).Fq().Neg(&s.V)
	return &v
}

func (s *Scalar[FE, T, W, WT]) Mul(x W) W {
	var v WT
	W(&v).Fq().Mul(&s.V, x.Fq())
	return &v
}

func (s *Scalar[FE, T, W, WT]) Square() W {
	var v WT
	W(&v).Fq().Square(&s.V)
	return &v
}

func (s *Scalar[FE, T, W, WT]) TryDiv(x W) (W, error) {
	var v WT
	if W(&v).Fq().Div(&s.V, x.Fq()) != 1 {
		return nil, errs.NewFailed("cannot divide")
	}
	return &v, nil
}

func (s *Scalar[FE, T, W, WT]) TryInv() (W, error) {
	var v WT
	if W(&v).Fq().Inv(&s.V) == 0 {
		return nil, errs.NewFailed("cannot invert")
	}
	return &v, nil
}

func (s *Scalar[FE, _, W, _]) Equal(x W) bool {
	return FE(&s.V).Equals(x.Fq()) == 1
}

func (s *Scalar[FE, _, W, _]) IsLessThanOrEqual(x W) bool {
	return ct.SliceCmpLE(FE(&s.V).Limbs(), x.Fq().Limbs()) == -1
}

func (s *Scalar[FE, _, _, _]) IsZero() bool {
	return FE(&s.V).IsZero() == 1
}

func (s *Scalar[FE, _, _, _]) IsOne() bool {
	return FE(&s.V).IsOne() == 1
}

func (s *Scalar[FE, _, _, _]) IsOdd() bool {
	return fieldsImpl.IsOdd[FE](&s.V) != 0
}

func (s *Scalar[FE, _, _, _]) IsEven() bool {
	return fieldsImpl.IsOdd[FE](&s.V) == 0
}

func (s *Scalar[FE, _, _, _]) IsNegative() bool {
	return fieldsImpl.IsNegative[FE](&s.V) != 0
}

func (s *Scalar[FE, _, _, _]) IsPositive() bool {
	return fieldsImpl.IsNegative[FE](&s.V) == 0
}

func (s *Scalar[FE, _, _, _]) HashCode() uint64 {
	h := fnv.New64a()

	for _, v := range FE(&s.V).ComponentsBytes() {
		_, _ = h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(v))))
		_, _ = h.Write(v)
	}

	return h.Sum64()
}

func (s *Scalar[FE, _, _, _]) MarshalBinary() ([]byte, error) {
	return FE(&s.V).Bytes(), nil
}

func (s *Scalar[FE, _, _, _]) Nat() *saferith.Nat {
	b := FE(&s.V).Bytes()
	slices.Reverse(b)
	return new(saferith.Nat).SetBytes(b)
}

func (s *Scalar[FE, T, W, WT]) Bytes() []byte {
	data := FE(&s.V).Bytes()
	slices.Reverse(data)
	return data
}

func (s *Scalar[FE, T, W, WT]) ComponentsBytes() [][]byte {
	cb := FE(&s.V).ComponentsBytes()
	for i := range cb {
		slices.Reverse(cb[i])
	}

	return cb
}

func (s *Scalar[_, _, W, _]) Op(x W) W {
	return s.Add(x)
}

func (s *Scalar[_, _, W, _]) OtherOp(x W) W {
	return s.Mul(x)
}

func (s *Scalar[_, _, _, _]) IsOpIdentity() bool {
	return s.IsZero()
}

func (s *Scalar[_, _, W, _]) OpInv() W {
	return s.Neg()
}

func (s *Scalar[_, _, W, _]) TryOpInv() (W, error) {
	return s.Neg(), nil
}

func (s *Scalar[_, _, W, _]) TryNeg() (W, error) {
	return s.Neg(), nil
}

func (s *Scalar[_, _, W, _]) TrySub(x W) (W, error) {
	return s.Sub(x), nil
}

func (s *Scalar[FE, _, _, _]) IsProbablyPrime() bool {
	b := FE(&s.V).Bytes()
	slices.Reverse(b)
	return new(big.Int).SetBytes(b).ProbablyPrime(0)
}

func (s *Scalar[_, _, W, WT]) EuclideanDiv(x W) (quot, rem W, err error) {
	quot, err = s.TryDiv(x)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "division by zero")
	}

	var r WT
	W(&r).Fq().SetZero()
	return quot, &r, nil
}
