package num

import (
	"fmt"
	"io"
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/cronokirby/saferith"
)

var (
	_ algebra.ZnLike[*Uint]   = (*Zn)(nil)
	_ algebra.UintLike[*Uint] = (*Uint)(nil)

	_ algebra.AdditiveModule[*Uint, *Uint]              = (*Zn)(nil)
	_ algebra.AdditiveModuleElement[*Uint, *Uint]       = (*Uint)(nil)
	_ algebra.MultiplicativeModule[*Uint, *Uint]        = (*Zn)(nil)
	_ algebra.MultiplicativeModuleElement[*Uint, *Uint] = (*Uint)(nil)
)

func NewZn(modulus *NatPlus) (*Zn, error) {
	if modulus == nil {
		return nil, errs.NewIsNil("modulus")
	}
	return &Zn{n: *modulus, safeN: saferith.ModulusFromNat(&modulus.v)}, nil
}

type Zn struct {
	n     NatPlus
	safeN *saferith.Modulus
}

func (zn *Zn) Name() string {
	return fmt.Sprintf("Z_(%s)", zn.n.String())
}

func (*Zn) Operator() algebra.BinaryOperator[*Uint] {
	return algebra.Add[*Uint]
}

func (*Zn) OtherOperator() algebra.BinaryOperator[*Uint] {
	return algebra.Mul[*Uint]
}

func (zn *Zn) Order() algebra.Cardinal {
	return &zn.Top().v
}

func (zn *Zn) Characteristic() algebra.Cardinal {
	return &zn.n.v
}

func (zn *Zn) Modulus() *NatPlus {
	return &zn.n
}

func (zn *Zn) ElementSize() int {
	return zn.n.AnnouncedLen()
}

func (zn *Zn) WideElementSize() int {
	return 2 * zn.ElementSize()
}

func (zn *Zn) FromUint64(value uint64) *Uint {
	out, err := zn.FromNat(N.FromUint64(value))
	if err != nil {
		panic(err)
	}
	return out
}

func (zn *Zn) FromInt64(value int64) *Uint {
	out, err := zn.FromInt(Z.FromInt64(value))
	if err != nil {
		panic(err)
	}
	return out
}

func (zn *Zn) FromInt(v *Int) (*Uint, error) {
	if v == nil {
		return nil, errs.NewIsNil("int")
	}
	return v.Mod(&zn.n), nil
}

func (zn *Zn) FromNat(v *Nat) (*Uint, error) {
	if v == nil {
		return nil, errs.NewIsNil("nat")
	}
	return v.Mod(&zn.n), nil
}

func (zn *Zn) FromSafeNat(v *saferith.Nat) (*Uint, error) {
	return zn.FromNat(&Nat{v: *v})
}

func (zn *Zn) OpIdentity() *Uint {
	return zn.Zero()
}

func (zn *Zn) Zero() *Uint {
	return &Uint{v: *zero, m: zn.safeN}
}

func (zn *Zn) One() *Uint {
	return &Uint{v: *one, m: zn.safeN}
}

func (zn *Zn) Top() *Uint {
	out, err := zn.FromNat(zn.n.Lift().Decrement().Abs())
	if err != nil {
		panic(err)
	}
	return out
}

func (*Zn) Random(prng io.Reader) (*Uint, error) {
	panic("implement me")
}

func (*Zn) Hash(bytes []byte) (*Uint, error) {
	panic("implement me")
}

func (zn *Zn) Iter() iter.Seq[*Uint] {
	return zn.IterRange(nil, nil)
}

func (zn *Zn) IterRange(start, stop *Uint) iter.Seq[*Uint] {
	return func(yield func(*Uint) bool) {
		if start == nil {
			start = zn.Zero()
		}
		if stop == nil {
			stop = zn.Top()
		}
		if !start.SameModulus(stop) || start.Compare(stop) == algebra.GreaterThan {
			return
		}
		cursor := start.Clone()
		for !cursor.Equal(stop) {
			if !yield(cursor) {
				return
			}
			cursor = cursor.Increment()
		}
	}
}

// func (z *Zn) Decompose(bases ...*saferith.Modulus) (*ResidueNumberSystem, error) {
// 	bs := new(saferith.Nat).SetUint64(1)
// 	for _, b := range bases {
// 		bs = new(saferith.Nat).Mul(bs, b.Nat(), -1)
// 	}
// 	if bs.Eq(z.n.Nat()) != 1 {
// 		return nil, errs.NewFailed("cannot decompose %s into %s", z.n.String(), bases)
// 	}
// 	return NewResidueNumberSystem(bases...)
// }

type Uint struct {
	v saferith.Nat
	m *saferith.Modulus
}

func (u *Uint) Structure() algebra.Structure[*Uint] {
	return &Zn{
		n:     NatPlus{v: u.v},
		safeN: u.m,
	}
}

func (u *Uint) Op(other *Uint) *Uint {
	if other == nil {
		panic("argument is nil")
	}
	return u.Add(other)
}

func (u *Uint) OtherOp(other *Uint) *Uint {
	if other == nil {
		panic("argument is nil")
	}
	return u.Mul(other)
}

func (u *Uint) TryOpInv() (*Uint, error) {
	return u.OpInv(), nil
}

func (u *Uint) OpInv() *Uint {
	return u.Neg()
}

func (u *Uint) Add(other *Uint) *Uint {
	if !u.SameModulus(other) {
		panic("cannot add elements from different Zn")
	}
	out := new(saferith.Nat).ModAdd(&other.v, &u.v, u.m)
	return &Uint{*out, u.m}
}

func (u *Uint) TrySub(other *Uint) (*Uint, error) {
	return u.Sub(other), nil
}

func (u *Uint) Sub(other *Uint) *Uint {
	if !u.SameModulus(other) {
		panic("cannot subtract elements from different Zn")
	}
	out := new(saferith.Nat).ModSub(&other.v, &u.v, u.m)
	return &Uint{*out, u.m}
}

func (u *Uint) Mul(other *Uint) *Uint {
	if !u.SameModulus(other) {
		panic("cannot multiply elements from different Zn")
	}
	out := new(saferith.Nat).ModMul(&other.v, &u.v, u.m)
	return &Uint{*out, u.m}
}

func (u *Uint) Exp(exponent *Uint) *Uint {
	if !u.SameModulus(exponent) {
		panic("cannot exponentiate elements from different Zn")
	}
	out := new(saferith.Nat).Exp(&exponent.v, &u.v, u.m)
	return &Uint{*out, u.m}
}

func (u *Uint) ExpI(exponent *Int) *Uint {
	if exponent == nil {
		panic("argument is nil")
	}
	out := new(saferith.Nat).ExpI(&u.v, &exponent.v, u.m)
	return &Uint{*out, u.m}
}

func (u *Uint) IsUnit() bool {
	return u.v.IsUnit(u.m) == 1
}

func (u *Uint) Coprime(other *Uint) bool {
	if other == nil {
		panic("argument is nil")
	}
	if !u.SameModulus(other) {
		panic("cannot compare elements from different Zn")
	}
	return u.v.Coprime(&other.v) == 1
}

func (u *Uint) IsProbablyPrime() bool {
	return u.v.Big().ProbablyPrime(0)
}

func (u *Uint) EuclideanDiv(other *Uint) (quot, rem *Uint, err error) {
	panic("implement me")
}

func (u *Uint) TryNeg() (*Uint, error) {
	return u.Neg(), nil
}

func (u *Uint) TryInv() (*Uint, error) {
	if !u.IsUnit() {
		return nil, errs.NewFailed("not a unit")
	}
	// TODO: check for even modulus
	out := new(saferith.Nat).ModInverse(&u.v, u.m)
	return &Uint{*out, u.m}, nil
}

func (u *Uint) TryDiv(other *Uint) (*Uint, error) {
	if !u.SameModulus(other) {
		panic("cannot divide elements from different Zn")
	}
	otherInv, err := other.TryInv()
	if err != nil {
		return nil, errs.WrapFailed(err, "argument is not invertible")
	}
	return u.Mul(otherInv), nil
}

func (u *Uint) Double() *Uint {
	return u.Add(u)
}

func (u *Uint) Square() *Uint {
	return u.Mul(u)
}

func (u *Uint) IsOpIdentity() bool {
	return u.IsZero()
}

func (u *Uint) IsZero() bool {
	return u.v.Eq(new(saferith.Nat).SetUint64(0)) == 1
}

func (u *Uint) IsOne() bool {
	return u.v.Eq(new(saferith.Nat).SetUint64(1)) == 1
}

func (u *Uint) PartialCompare(other *Uint) algebra.PartialOrdering {
	if other == nil {
		panic("argument is nil")
	}
	comparability := u.m.Nat().Eq(other.m.Nat())
	gt, eq, lt := u.v.Cmp(&other.v)
	outComparable := algebra.PartialOrdering(-1*int(lt) + 0*int(eq) + 1*int(gt))
	return ct.Select(uint64(comparability), algebra.Incomparable, outComparable)
}

func (u *Uint) Compare(other *Uint) algebra.Ordering {
	if other == nil {
		panic("argument is nil")
	}
	if !u.SameModulus(other) {
		panic("cannot compare elements from different Zn")
	}
	gt, eq, lt := u.v.Cmp(&other.v)
	return algebra.Ordering(-1*int(lt) + 0*int(eq) + 1*int(gt))
}

func (u *Uint) IsLessThanOrEqual(other *Uint) bool {
	cmp := u.PartialCompare(other)
	return cmp != algebra.GreaterThanOrIncomparable && cmp != algebra.Incomparable
}

func (u *Uint) SameModulus(other *Uint) bool {
	if other == nil {
		panic("argument is nil")
	}
	return u.m.Nat().Eq(other.m.Nat()) == 1
}

func (u *Uint) Equal(other *Uint) bool {
	if !u.SameModulus(other) {
		panic("cannot compare elements from different Zn")
	}
	return u.v.Eq(&other.v) == 1
}

func (u *Uint) Sqrt() (*Uint, error) {
	// TODO: worry about the case when modulus is not prime.
	// TODO: worry about the case when u does not have a square root.
	out := new(saferith.Nat).ModSqrt(&u.v, u.m)
	return &Uint{*out, u.m}, nil
}

func (u *Uint) Neg() *Uint {
	out := new(saferith.Nat).ModNeg(&u.v, u.m)
	return &Uint{*out, u.m}
}

func (u *Uint) ScalarOp(other *Uint) *Uint {
	return u.Mul(other)
}

func (u *Uint) IsTorsionFree() bool {
	return true
}

func (u *Uint) ScalarMul(other *Uint) *Uint {
	return u.Mul(other)
}

func (u *Uint) ScalarExp(other *Uint) *Uint {
	return u.Exp(other)
}

func (u *Uint) SafeNat() *saferith.Nat {
	return &u.v
}

func (u *Uint) Clone() *Uint {
	return &Uint{*u.v.Clone(), u.m}
}

func (u *Uint) Lift() *Int {
	return &Int{v: *new(saferith.Int).SetNat(&u.v)}
}

func (u *Uint) HashCode() uint64 {
	return u.v.Uint64() % u.m.Nat().Uint64()
}

func (u *Uint) Modulus() *NatPlus {
	return &NatPlus{v: *u.m.Nat()}
}

func (u *Uint) String() string {
	return u.v.String()
}

func (u *Uint) Increment() *Uint {
	return u.Add(&Uint{*one, u.m})
}

func (u *Uint) Decrement() *Uint {
	return u.Sub(&Uint{*one, u.m})
}

func (u *Uint) Bytes() []byte {
	return u.v.Bytes()
}

func (u *Uint) Bit(i int) uint8 {
	return u.v.Byte(i)
}

func (u *Uint) IsEven() bool {
	return u.Bit(0) == 0
}

func (u *Uint) IsOdd() bool {
	return u.Bit(0) == 1
}

func (u *Uint) TrueLen() int {
	return u.v.TrueLen()
}

func (u *Uint) AnnouncedLen() int {
	return u.v.AnnouncedLen()
}

func (u *Uint) MarshalBinary() ([]byte, error) {
	panic("implement me")
}

func (u *Uint) UnmarshalBinary(data []byte) error {
	panic("implement me")
}
