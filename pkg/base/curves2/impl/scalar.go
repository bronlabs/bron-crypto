package impl

import (
	"encoding/binary"
	"hash/fnv"
	"math/big"
	"slices"

	"github.com/bronlabs/krypton-primitives/pkg/base/ct"
	fieldsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves2/impl/fields"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/cronokirby/saferith"
)

type Scalar[FE fieldsImpl.PrimeFieldElementPtrConstraint[FE, T], T any] struct {
	v T
}

func (s *Scalar[FE, _]) MarshalBinary() ([]byte, error) {
	return FE(&s.v).Bytes(), nil
}

func (s *Scalar[_, _]) UnmarshalBinary(data []byte) error {
	panic("implement me")
}

func (s *Scalar[FE, T]) Op(x *Scalar[FE, T]) *Scalar[FE, T] {
	return s.Add(x)
}

func (s *Scalar[FE, T]) OtherOp(x *Scalar[FE, T]) *Scalar[FE, T] {
	return s.Mul(x)
}

func (s *Scalar[FE, T]) Add(x *Scalar[FE, T]) *Scalar[FE, T] {
	var out Scalar[FE, T]
	FE(&out.v).Add(&s.v, &x.v)
	return &out
}

func (s *Scalar[FE, T]) Mul(x *Scalar[FE, T]) *Scalar[FE, T] {
	var out Scalar[FE, T]
	FE(&out.v).Mul(&s.v, &x.v)
	return &out
}

func (s *Scalar[FE, T]) Equal(x *Scalar[FE, T]) bool {
	return FE(&s.v).Equals(&x.v) == 1
}

func (s *Scalar[FE, _]) IsZero() bool {
	return FE(&s.v).IsZero() == 1
}

func (s *Scalar[FE, _]) IsOne() bool {
	return FE(&s.v).IsOne() == 1
}

func (s *Scalar[_, _]) IsOpIdentity() bool {
	return s.IsZero()
}

func (s *Scalar[FE, T]) OpInv() *Scalar[FE, T] {
	return s.Neg()
}

func (s *Scalar[FE, T]) TryOpInv() (*Scalar[FE, T], error) {
	return s.Neg(), nil
}

func (s *Scalar[FE, T]) Neg() *Scalar[FE, T] {
	var out Scalar[FE, T]
	FE(&out.v).Neg(&s.v)
	return &out
}

func (s *Scalar[FE, T]) TryNeg() (*Scalar[FE, T], error) {
	return s.Neg(), nil
}

func (s *Scalar[FE, T]) Sub(x *Scalar[FE, T]) *Scalar[FE, T] {
	var out Scalar[FE, T]
	FE(&out.v).Sub(&s.v, &x.v)
	return &out
}

func (s *Scalar[FE, T]) TrySub(x *Scalar[FE, T]) (*Scalar[FE, T], error) {
	return s.Sub(x), nil
}

func (s *Scalar[FE, T]) Double() *Scalar[FE, T] {
	return s.Add(s)
}

func (s *Scalar[FE, T]) Square() *Scalar[FE, T] {
	var out Scalar[FE, T]
	FE(&out.v).Square(&s.v)
	return &out
}

func (s *Scalar[FE, T]) Clone() *Scalar[FE, T] {
	return &Scalar[FE, T]{v: s.v}
}

func (s Scalar[FE, _]) HashCode() uint64 {
	h := fnv.New64a()
	buf := make([]byte, 8)

	for _, v := range FE(&s.v).Limbs() {
		binary.LittleEndian.PutUint64(buf, v)
		h.Write(buf)
	}

	return h.Sum64()
}

func (s *Scalar[FE, T]) TryDiv(x *Scalar[FE, T]) (*Scalar[FE, T], error) {
	var v T
	if FE(&v).Div(&s.v, &x.v) != 1 {
		return nil, errs.NewFailed("cannot divide")
	}
	return &Scalar[FE, T]{v: v}, nil
}

func (s *Scalar[FE, T]) TryInv() (*Scalar[FE, T], error) {
	var v T
	if FE(&v).Inv(&s.v) == 1 {
		return nil, errs.NewFailed("cannot invert")
	}
	return &Scalar[FE, T]{v: v}, nil
}

func (s *Scalar[FE, T]) IsLessThanOrEqual(x *Scalar[FE, T]) bool {
	return ct.SliceCmpLE(FE(&s.v).Limbs(), FE(&x.v).Limbs()) == -1
}

func (s *Scalar[FE, T]) IsProbablyPrime() bool {
	b := FE(&s.v).Bytes()
	slices.Reverse(b)
	return new(big.Int).SetBytes(b).ProbablyPrime(0)
}

func (s *Scalar[FE, T]) Nat() *saferith.Nat {
	b := FE(&s.v).Bytes()
	slices.Reverse(b)
	return new(saferith.Nat).SetBytes(b)
}

func (s *Scalar[FE, T]) EuclideanDiv(x *Scalar[FE, T]) (quot, rem *Scalar[FE, T], err error) {
	panic("implement me")
}
