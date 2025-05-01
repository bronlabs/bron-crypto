package num

import (
	"iter"
	"math/big"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/cronokirby/saferith"
)

var (
	_ algebra.ZLike[*Int]   = (*z)(nil)
	_ algebra.IntLike[*Int] = (*Int)(nil)

	_ algebra.AdditiveModule[*Int, *Int]              = (*z)(nil)
	_ algebra.AdditiveModuleElement[*Int, *Int]       = (*Int)(nil)
	_ algebra.MultiplicativeModule[*Int, *Int]        = (*z)(nil)
	_ algebra.MultiplicativeModuleElement[*Int, *Int] = (*Int)(nil)

	zeroInt = new(saferith.Int).SetUint64(0)
	oneInt  = new(saferith.Int).SetUint64(1)

	Z = &z{}
)

type z struct{}

func (*z) Name() string {
	return "Z"
}

func (*z) Operator() algebra.BinaryOperator[*Int] {
	return algebra.Add[*Int]
}

func (*z) OtherOperator() algebra.BinaryOperator[*Int] {
	return algebra.Mul[*Int]
}

func (*z) Order() algebra.Cardinal {
	return algebra.Infinite
}

func (*z) Characteristic() algebra.Cardinal {
	return zero
}

func (zs *z) OpIdentity() *Int {
	return zs.Zero()
}

func (*z) Zero() *Int {
	return &Int{v: *zeroInt}
}

func (*z) One() *Int {
	return &Int{v: *oneInt}
}

func (*z) FromUint64(value uint64) *Int {
	out := new(saferith.Int).SetUint64(value)
	return &Int{v: *out}
}

func (*z) FromNat(value *saferith.Nat) *Int {
	if value == nil {
		return nil
	}
	out := new(saferith.Int).SetNat(value)
	return &Int{v: *out}
}

func (*z) FromInt64(value int64) *Int {
	var abs uint64
	if value < 0 {
		abs = uint64(-value)
	} else {
		abs = uint64(value)
	}
	v := new(saferith.Int).SetUint64(abs)
	out := &Int{v: *v}
	if value < 0 {
		out.v.Neg(1)
	}
	return out
}

func (*z) FromBytes(input []byte) (*Int, error) {
	if input == nil {
		return nil, errs.NewIsNil("input must not be empty")
	}

	b := new(big.Int).SetBytes(input)
	signed := new(saferith.Int).SetBig(b, -1)

	return &Int{v: *signed}, nil
}

func (zs *z) Iter() iter.Seq[*Int] {
	return zs.IterRange(zs.Zero(), nil)
}

func (*z) IterRange(start, stop *Int) iter.Seq[*Int] {
	if start == nil {
		return nil
	}
	cursor := start.Clone()
	var direction func(*Int) *Int
	if stop == nil {
		direction = func(i *Int) *Int { return i.Increment() }
		if start.IsNegative() {
			direction = func(i *Int) *Int { return i.Decrement() }
		}
		return func(yield func(*Int) bool) {
			for {
				if !yield(cursor) {
					return
				}
				cursor = direction(cursor)
			}
		}
	}
	if start.Compare(stop) == algebra.GreaterThan {
		return nil
	}
	return func(yield func(*Int) bool) {
		switch stop.Compare(start) {
		case algebra.GreaterThan:
			direction = func(i *Int) *Int { return i.Increment() }
		case algebra.LessThan:
			direction = func(i *Int) *Int { return i.Decrement() }
		case algebra.Equal:
			_ = yield(start)
			return
		}

		for !start.Equal(stop) {
			if !yield(start) {
				return
			}
			start = direction(start)
		}
	}
}

type Int struct {
	v saferith.Int
}

func (i *Int) Structure() algebra.Structure[*Int] {
	return &z{}
}

func (i *Int) Op(other *Int) *Int {
	if other == nil {
		panic("argument is nil")
	}
	return i.Add(other)
}

func (i *Int) TryOpInv() (*Int, error) {
	return i.OpInv(), nil
}

func (i *Int) OpInv() *Int {
	return i.Neg()
}

func (i *Int) OtherOp(other *Int) *Int {
	if other == nil {
		panic("argument is nil")
	}
	return i.Mul(other)
}

func (i *Int) Add(other *Int) *Int {
	return i.AddCap(other, -1)
}

func (i *Int) AddCap(other *Int, cap int) *Int {
	if other == nil {
		panic("argument is nil")
	}
	out := new(saferith.Int).Add(&i.v, &other.v, cap)
	return &Int{v: *out}
}

func (i *Int) TrySub(other *Int) (*Int, error) {
	if other == nil {
		panic("argument is nil")
	}
	return i.Sub(other), nil
}

func (i *Int) Sub(other *Int) *Int {
	return i.SubCap(other, -1)
}

func (i *Int) SubCap(other *Int, cap int) *Int {
	if other == nil {
		panic("argument is nil")
	}
	return i.AddCap(other.Neg(), cap)
}

func (i *Int) Mul(other *Int) *Int {
	return i.MulCap(other, -1)
}

func (i *Int) MulCap(other *Int, cap int) *Int {
	if other == nil {
		panic("argument is nil")
	}
	out := new(saferith.Int).Mul(&i.v, &other.v, cap)
	return &Int{v: *out}
}

func (i *Int) Exp(other *Int) *Int {
	if other == nil {
		panic("argument is nil")
	}
	panic("not implemented")
}

func (i *Int) IsInRange(modulus *NatPlus) bool {
	if modulus == nil {
		panic("argument is nil")
	}
	return i.v.CheckInRange(saferith.ModulusFromNat(&modulus.v)) == 1
}

func (i *Int) Mod(modulus *NatPlus) *Uint {
	if modulus == nil {
		panic("argument is nil")
	}
	m := saferith.ModulusFromNat(&modulus.v)
	v := i.v.Mod(m)
	return &Uint{v: *v, m: m}
}

func (i *Int) Coprime(other *Int) bool {
	if other == nil {
		panic("argument is nil")
	}
	return i.Abs().Coprime(other.Abs())
}

func (i *Int) IsProbablyPrime() bool {
	return i.v.Big().ProbablyPrime(0)
}

func (i *Int) EuclideanDiv(other *Int) (quot, rem *Int, err error) {
	if other == nil {
		panic("argument is nil")
	}
	q, r, err := i.Abs().EuclideanDiv(other.Abs())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "division failed")
	}
	if i.IsNegative() != other.IsNegative() {
		quot = q.Lift().Neg()
	}
	return quot, r.Lift(), nil
}

func (i *Int) Abs() *Nat {
	return &Nat{v: *i.v.Abs()}
}

func (i *Int) IsNegative() bool {
	return i.v.IsNegative() == 1
}

func (i *Int) TryDiv(other *Int) (*Int, error) {
	if other == nil {
		panic("argument is nil")
	}
	quot, rem, err := i.EuclideanDiv(other)
	if err != nil {
		return nil, errs.WrapFailed(err, "division failed")
	}
	if !rem.IsZero() {
		return nil, errs.NewValue("division not exact")
	}
	return quot, nil
}

func (i *Int) TryInv() (*Int, error) {
	return nil, errs.NewValue("no multiplicative inverse for int")
}

func (i *Int) TryNeg() (*Int, error) {
	return i.Neg(), nil
}

func (i *Int) Neg() *Int {
	return &Int{v: *i.v.Clone().Neg(1)}
}

func (i *Int) Double() *Int {
	return i.AddCap(i, i.v.AnnouncedLen()+1)
}

func (i *Int) Square() *Int {
	return i.Mul(i)
}

func (i *Int) Compare(other *Int) algebra.Ordering {
	if other == nil {
		panic("argument is nil")
	}

	// Equal case (constant-time Eq returns 1 for equality)
	if i.Equal(other) {
		return algebra.Equal
	}

	iAbs := i.Abs()
	oAbs := other.Abs()

	gt, eq, lt := iAbs.v.Cmp(&oAbs.v)

	// sign bits: 1 if negative, 0 if non-negative
	iNeg := int(i.v.IsNegative())
	oNeg := int(other.v.IsNegative())

	// Different signs: (iNeg, oNeg) → result
	// iNeg=1, oNeg=0 → LT
	// iNeg=0, oNeg=1 → GT
	// same sign → compare abs
	sameSign := 1 - (iNeg ^ oNeg)

	// If both negative, reverse abs compare
	reversed := iNeg & sameSign

	// Combine: use abs compare if sameSign == 1, otherwise use sign comparison
	// result = (1 - sameSign) * signComp + sameSign * (if reversed then reverse(absComp) else absComp)

	absComp := -1*int(lt) + 0*int(eq) + 1*int(gt)
	reversedComp := -1 * absComp

	signComp := -1*iNeg + 1*oNeg // if iNeg=1,oNeg=0 → -1; if iNeg=0,oNeg=1 → +1

	res := (1 - int(sameSign)) * signComp
	res += sameSign * ((1-reversed)*absComp + reversed*reversedComp)

	return algebra.Ordering(res)
}

func (i *Int) IsLessThanOrEqual(other *Int) bool {
	return i.Compare(other) != algebra.GreaterThan
}

func (i *Int) Equal(other *Int) bool {
	if other == nil {
		panic("argument is nil")
	}
	return i.v.Eq(&other.v) == 1
}

func (i *Int) IsOpIdentity() bool {
	return i.IsZero()
}

func (i *Int) ScalarOp(other *Int) *Int {
	return i.Mul(other)
}

func (i *Int) IsTorsionFree() bool {
	return true
}

func (i *Int) ScalarMul(other *Int) *Int {
	return i.Mul(other)
}

func (i *Int) ScalarExp(other *Int) *Int {
	return i.Exp(other)
}

func (i *Int) IsZero() bool {
	return i.v.Eq(new(saferith.Int).SetUint64(0)) == 1
}

func (i *Int) IsOne() bool {
	return i.v.Eq(new(saferith.Int).SetUint64(1)) == 1
}

func (i *Int) HashCode() uint64 {
	return i.v.Abs().Uint64()
}

func (i *Int) Clone() *Int {
	return &Int{v: *i.v.Clone()}
}

func (i *Int) String() string {
	return i.v.String()
}

func (i *Int) Increment() *Int {
	return i.Add(Z.One())
}

func (i *Int) Decrement() *Int {
	return i.Sub(Z.One())
}

func (i *Int) Bytes() []byte {
	return i.v.Big().Bytes()
}

func (n *Int) Bit(i int) uint8 {
	return uint8(n.v.Big().Bit(i))
}

func (n *Int) IsEven() bool {
	return n.Bit(0) == 0
}

func (n *Int) IsOdd() bool {
	return n.Bit(0) == 1
}

func (i *Int) TrueLen() int {
	return i.v.TrueLen()
}

func (i *Int) AnnouncedLen() int {
	return i.v.AnnouncedLen()
}

func (i *Int) MarshalBinary() ([]byte, error) {
	panic("implement me")
}

func (i *Int) UnmarshalBinary(data []byte) error {
	panic("implement me")
}
