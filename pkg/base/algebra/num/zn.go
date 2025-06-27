package num

import (
	"fmt"
	"io"
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/num/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	saferith_utils "github.com/bronlabs/bron-crypto/pkg/base/utils/saferith"
	"github.com/cronokirby/saferith"
	"golang.org/x/crypto/blake2b"
)

var (
	_ algebra.ZnLike[*Uint]   = (*Zn)(nil)
	_ algebra.UintLike[*Uint] = (*Uint)(nil)

	_ algebra.AdditiveModule[*Uint, *Uint]        = (*Zn)(nil)
	_ algebra.AdditiveModuleElement[*Uint, *Uint] = (*Uint)(nil)
)

func NewZn(modulus cardinal.Cardinal) (*Zn, error) {
	if modulus == nil {
		return nil, errs.NewIsNil("modulus")
	}
	if modulus.IsZero() {
		return nil, errs.NewValue("modulus must not be zero")
	}
	n := &NatPlus{v: *new(saferith.Nat).SetBytes(modulus.Bytes())}
	return &Zn{n: *n, safeN: saferith.ModulusFromNat(&n.v)}, nil
}

type Zn struct {
	n     NatPlus
	safeN *saferith.Modulus
}

func (zn *Zn) Name() string {
	return fmt.Sprintf("Z\\%sZ", zn.n.String())
}

func (zn *Zn) Order() cardinal.Cardinal {
	return cardinal.FromNat(zn.Top().Lift().Increment().v.Abs())
}

func (zn *Zn) Characteristic() cardinal.Cardinal {
	return cardinal.FromNat(&zn.n.v)
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
	out, err := zn.FromNat(N().FromUint64(value))
	if err != nil {
		panic(err)
	}
	return out
}

func (zn *Zn) FromInt64(value int64) *Uint {
	out, err := zn.FromInt(Z().FromInt64(value))
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

func (zn *Zn) FromBytes(input []byte) (*Uint, error) {
	if input == nil {
		return nil, errs.NewIsNil("input")
	}
	v, err := N().FromBytes(input)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to deserialize Nat from bytes")
	}
	return zn.FromNat(v)
}

func (zn *Zn) FromNat(v *Nat) (*Uint, error) {
	if v == nil {
		return nil, errs.NewIsNil("nat")
	}
	return v.Mod(&zn.n), nil
}

func (zn *Zn) FromCardinal(v cardinal.Cardinal) (*Uint, error) {
	return zn.FromBytes(v.Bytes())
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

func (zn *Zn) Random(prng io.Reader) (*Uint, error) {
	out, err := saferith_utils.NatRandomRangeH(prng, zn.safeN.Nat())
	if err != nil {
		return nil, errs.WrapRandomSample(err, "failed to sample random element in Zn")
	}
	return &Uint{v: *out, m: zn.safeN}, nil
}

func (zn *Zn) Hash(input []byte) (*Uint, error) {
	xof, err := blake2b.NewXOF(uint32(zn.WideElementSize()), nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create blake2b XOF")
	}
	xof.Write(input)
	digest := make([]byte, zn.WideElementSize())
	if _, err = io.ReadFull(xof, digest); err != nil {
		return nil, errs.WrapSerialisation(err, "failed to read full blake2b XOF output")
	}
	n := new(saferith.Nat).SetBytes(digest[:])
	v := new(saferith.Nat).Mod(n, zn.safeN)
	return &Uint{v: *v, m: zn.safeN}, nil
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
		if !start.SameModulus(stop) || start.Compare(stop) == base.GreaterThan {
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

func (zn *Zn) MultiScalarOp(scs []*Uint, es []*Uint) (*Uint, error) {
	return zn.MultiScalarMul(scs, es)
}

func (zs *Zn) MultiScalarMul(scs []*Uint, es []*Uint) (*Uint, error) {
	if len(scs) != len(es) {
		return nil, errs.NewLength("scalars and exponents must have the same length")
	}
	if len(scs) == 0 {
		return nil, errs.NewLength("no scalars provided")
	}

	out := zs.Zero()
	for i, sc := range scs {
		if sc == nil || es[i] == nil {
			return nil, errs.NewIsNil("scalar or exponent is nil")
		}
		out = out.Add(sc.Mul(es[i]))
	}
	return out, nil
}

func (zn *Zn) IsDomain() bool {
	return zn.Modulus().Lift().IsProbablyPrime()
}

func (zn *Zn) ScalarStructure() algebra.Structure[*Uint] {
	return zn
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
		n:     NatPlus{v: *u.m.Nat()},
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

func (u *Uint) IsNegative() bool {
	return false
}

func (u *Uint) TryOpInv() (*Uint, error) {
	return u.OpInv(), nil
}

func (u *Uint) OpInv() *Uint {
	return u.Neg()
}

func (u *Uint) IsPositive() bool {
	return !u.IsZero()
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
	out := new(saferith.Nat).ModSub(&u.v, &other.v, u.m)
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

func (u *Uint) PartialCompare(other *Uint) base.PartialOrdering {
	if other == nil {
		panic("argument is nil")
	}
	comparability := u.m.Nat().Eq(other.m.Nat())
	gt, eq, lt := u.v.Cmp(&other.v)
	outComparable := base.PartialOrdering(-1*int(lt) + 0*int(eq) + 1*int(gt))
	return ct.Select(uint64(comparability), base.Incomparable, outComparable)
}

func (u *Uint) Compare(other *Uint) base.Ordering {
	if other == nil {
		panic("argument is nil")
	}
	if !u.SameModulus(other) {
		panic("cannot compare elements from different Zn")
	}
	gt, eq, lt := u.v.Cmp(&other.v)
	return base.Ordering(-1*int(lt) + 0*int(eq) + 1*int(gt))
}

func (u *Uint) IsLessThanOrEqual(other *Uint) bool {
	cmp := u.PartialCompare(other)
	return cmp != base.GreaterThanOrIncomparable && cmp != base.Incomparable
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

func (u *Uint) Cardinal() cardinal.Cardinal {
	return cardinal.FromNat(&u.v)
}

func (u *Uint) Clone() *Uint {
	return &Uint{*u.v.Clone(), u.m}
}

func (u *Uint) Lift() *Int {
	return &Int{v: *new(saferith.Int).SetNat(&u.v)}
}

func (u *Uint) HashCode() base.HashCode {
	return base.HashCode(u.v.Uint64() % u.m.Nat().Uint64())
}

func (u *Uint) Modulus() *NatPlus {
	return &NatPlus{v: *u.m.Nat()}
}

func (u *Uint) String() string {
	return u.v.Big().String()
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
