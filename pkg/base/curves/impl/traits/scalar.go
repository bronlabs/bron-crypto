package traits

import (
	"encoding/binary"
	"hash/fnv"
	"math/big"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/fields"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/cronokirby/saferith"
)

type ScalarTraitInheriter[FE fields.PrimeFieldElementPtrConstraint[FE, FET], FET any] interface {
	SetFq(FET)
	Fq() FE
}

type ScalarTraitInheriterPtrConstraint[FE fields.PrimeFieldElementPtrConstraint[FE, FET], FET any, WT any] interface {
	*WT
	ScalarTraitInheriter[FE, FET]
}

type ScalarField[FE fields.PrimeFieldElementPtrConstraint[FE, T], T any, W ScalarTraitInheriterPtrConstraint[FE, T, WT], WT any] struct {
	_ ds.Incomparable
}

func (f ScalarField[FE, T, W, WT]) SubFieldIdentity(i uint) (any, error) {
	if i == 1 {
		return f.OpIdentity(), nil
	}
	var out W
	return out, errs.NewValue("invalid subfield index")
}

func (f ScalarField[FE, T, W, WT]) Zero() W {
	var v T
	FE(&v).SetZero()
	var out WT
	W(&out).SetFq(v)
	return W(&out)
}

func (f ScalarField[FE, T, W, WT]) One() W {
	var v T
	FE(&v).SetOne()
	var out WT
	W(&out).SetFq(v)
	return W(&out)
}

func (f ScalarField[FE, T, W, WT]) OpIdentity() W {
	return f.Zero()
}

func (f ScalarField[FE, T, W, WT]) Compare(x, y W) algebra.Ordering {
	return algebra.Ordering(ct.SliceCmpLE(x.Fq().Limbs(), y.Fq().Limbs()))
}

func (f ScalarField[FE, T, W, WT]) PartialCompare(x, y W) algebra.PartialOrdering {
	return algebra.PartialOrdering(f.Compare(x, y))
}

func NewScalarFromNat[FE fields.PrimeFieldElementPtrConstraint[FE, T], T any, W ScalarTraitInheriterPtrConstraint[FE, T, WT], WT any](input *saferith.Nat, fieldOrder *saferith.Modulus) (W, error) {
	if input == nil || fieldOrder == nil {
		return nil, errs.NewIsNil("argument")
	}
	reducedV := new(saferith.Nat).Mod(input, fieldOrder)
	vBytes := reducedV.Bytes()
	slices.Reverse(vBytes)

	var v T
	ok := FE(&v).SetBytesWide(vBytes)
	if ok != 1 {
		return nil, errs.NewFailed("cannot set scalar")
	}
	var out WT
	W(&out).SetFq(v)
	return W(&out), nil
}

type Scalar[FE fields.PrimeFieldElementPtrConstraint[FE, T], T any, W ScalarTraitInheriterPtrConstraint[FE, T, WT], WT any] struct {
	V T
}

func (s *Scalar[FE, _, _, _]) MarshalBinary() ([]byte, error) {
	return FE(&s.V).Bytes(), nil
}

func (s *Scalar[_, _, W, _]) Op(x W) W {
	return s.Add(x)
}

func (s *Scalar[_, _, W, _]) OtherOp(x W) W {
	return s.Mul(x)
}

func (s *Scalar[FE, T, W, WT]) Add(x W) W {
	var v T
	FE(&v).Add(&s.V, x.Fq())
	var out WT
	W(&out).SetFq(v)
	return W(&out)
}

func (s *Scalar[FE, T, W, WT]) Mul(x W) W {
	var v T
	FE(&v).Mul(&s.V, x.Fq())
	var out WT
	W(&out).SetFq(v)
	return W(&out)
}

func (s *Scalar[FE, _, W, _]) Equal(x W) bool {
	return FE(&s.V).Equals(x.Fq()) == 1
}

func (s *Scalar[FE, _, _, _]) IsZero() bool {
	return FE(&s.V).IsZero() == 1
}

func (s *Scalar[FE, _, _, _]) IsOne() bool {
	return FE(&s.V).IsOne() == 1
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

func (s *Scalar[FE, T, W, WT]) Neg() W {
	var v T
	FE(&v).Neg(&s.V)
	var out WT
	W(&out).SetFq(v)
	return W(&out)
}

func (s *Scalar[_, _, W, _]) TryNeg() (W, error) {
	return s.Neg(), nil
}

func (s *Scalar[FE, T, W, WT]) Sub(x W) W {
	var v T
	FE(&v).Sub(&s.V, x.Fq())
	var out WT
	W(&out).SetFq(v)
	return W(&out)
}

func (s *Scalar[_, _, W, _]) TrySub(x W) (W, error) {
	return s.Sub(x), nil
}

func (s *Scalar[_, _, W, _]) Double() W {
	return s.Add(s.Clone())
}

func (s *Scalar[FE, T, W, WT]) Square() W {
	var v T
	FE(&v).Square(&s.V)
	var out WT
	W(&out).SetFq(v)
	return W(&out)
}

func (s *Scalar[_, _, W, WT]) Clone() W {
	var out WT
	W(&out).SetFq(s.V)
	return W(&out)
}

func (s Scalar[FE, _, _, _]) HashCode() uint64 {
	h := fnv.New64a()
	buf := make([]byte, 8)

	for _, v := range FE(&s.V).Limbs() {
		binary.LittleEndian.PutUint64(buf, v)
		h.Write(buf)
	}

	return h.Sum64()
}

func (s *Scalar[FE, T, W, WT]) TryDiv(x W) (W, error) {
	var v T
	if FE(&v).Div(&s.V, x.Fq()) != 1 {
		return nil, errs.NewFailed("cannot divide")
	}
	var out WT
	W(&out).SetFq(v)
	return W(&out), nil
}

func (s *Scalar[FE, T, W, WT]) TryInv() (W, error) {
	var v T
	if FE(&v).Inv(&s.V) == 1 {
		return nil, errs.NewFailed("cannot invert")
	}
	var out WT
	W(&out).SetFq(v)
	return W(&out), nil
}

func (s *Scalar[FE, _, W, _]) IsLessThanOrEqual(x W) bool {
	return ct.SliceCmpLE(FE(&s.V).Limbs(), x.Fq().Limbs()) == -1
}

func (s *Scalar[FE, _, _, _]) IsProbablyPrime() bool {
	b := FE(&s.V).Bytes()
	slices.Reverse(b)
	return new(big.Int).SetBytes(b).ProbablyPrime(0)
}

func (s *Scalar[FE, _, _, _]) Nat() *saferith.Nat {
	b := FE(&s.V).Bytes()
	slices.Reverse(b)
	return new(saferith.Nat).SetBytes(b)
}

func (s *Scalar[_, _, W, _]) EuclideanDiv(x W) (quot, rem W, err error) {
	panic("implement me")
}
