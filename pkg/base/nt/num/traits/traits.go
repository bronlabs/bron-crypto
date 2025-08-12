package traits

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	saferith_utils "github.com/bronlabs/bron-crypto/pkg/base/utils/saferith"
	"github.com/cronokirby/saferith"
)

type Number[E any] interface {
	set(*saferith.Nat) error
	value() *saferith.Nat
}

type NumberInheritter[E any] interface {
	Number[E]
}

type NumberInheritterPtrConstraint[E, T any] interface {
	*T
	NumberInheritter[E]
}

// NatPlus

type NPlus[S algebra.NPlusLike[E], E algebra.NatPlusLike[E], W NumberInheritterPtrConstraint[E, WT], WT any] struct {
}

func (*NPlus[S, E, W, WT]) Name() string {
	return "N+"
}

func (*NPlus[S, E, W, WT]) Characteristic() cardinal.Cardinal {
	return cardinal.Zero()
}

func (*NPlus[S, E, W, WT]) Order() cardinal.Cardinal {
	return cardinal.Infinite()
}

func (*NPlus[S, E, W, WT]) One() W {
	var out WT
	if err := W(&out).set(saferith_utils.NatOne); err != nil {
		panic(err)
	}
	return W(&out)
}

type NatPlus[E algebra.NatPlusLike[E], W NumberInheritterPtrConstraint[E, WT], WT any] struct {
	v *saferith.Nat
}

func (n *NatPlus[E, W, WT]) set(v *saferith.Nat) error {
	if n == nil {
		return errs.NewValue("receiver cannot be nil")
	}
	if v == nil {
		return errs.NewValue("value cannot be nil")
	}
	if gt, _, _ := n.v.Cmp(saferith_utils.NatZero); gt != 1 {
		return errs.NewValue("value must be greater than 0")
	}
	n.v = v
	return nil
}

func (n *NatPlus[E, W, WT]) value() *saferith.Nat {
	if n == nil {
		return nil
	}
	return n.v
}

func (n *NatPlus[E, W, WT]) IsPositive() bool {
	return n != nil
}

func (n *NatPlus[E, W, WT]) Add(other W) W {
	return n.AddCap(other, -1)
}

func (n *NatPlus[E, W, WT]) AddCap(other W, cap algebra.Capacity) W {
	if other == nil {
		panic("argument is nil")
	}
	out := new(saferith.Nat).Add(n.v, other.value(), cap)
	var res WT
	if err := W(&res).set(out); err != nil {
		panic(errs.WrapFailed(err, "failed to add"))
	}
	return W(&res)
}

// func (i *unboundedTrait) Op(other *Int) *Int {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	return i.Add(other)
// }

// func (i *unboundedTrait) TryOpInv() (*Int, error) {
// 	return i.OpInv(), nil
// }

// func (i *unboundedTrait) OpInv() *Int {
// 	return i.Neg()
// }

// func (i *unboundedTrait) OtherOp(other *Int) *Int {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	return i.Mul(other)
// }

// func (i *unboundedTrait) Add(other *Int) *Int {
// 	return i.AddCap(other, -1)
// }

// func (i *unboundedTrait) AddCap(other *Int, cap int) *Int {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	out := new(saferith.Int).Add(&i.v, &other.v, cap)
// 	return &Int{v: *out}
// }

// func (i *unboundedTrait) TrySub(other *Int) (*Int, error) {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	return i.Sub(other), nil
// }

// func (i *unboundedTrait) Sub(other *Int) *Int {
// 	return i.SubCap(other, -1)
// }

// func (i *unboundedTrait) SubCap(other *Int, cap int) *Int {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	return i.AddCap(other.Neg(), cap)
// }

// func (i *unboundedTrait) Mul(other *Int) *Int {
// 	return i.MulCap(other, -1)
// }

// func (i *unboundedTrait) MulCap(other *Int, cap int) *Int {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	out := new(saferith.Int).Mul(&i.v, &other.v, cap)
// 	return &Int{v: *out}
// }

// func (i *unboundedTrait) Exp(other *Int) *Int {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	// Handle special cases
// 	if other.IsZero() {
// 		return Z().One()
// 	}
// 	if other.IsNegative() {
// 		panic("negative exponent not supported for integers")
// 	}
// 	if i.IsZero() {
// 		return Z().Zero()
// 	}

// 	// Perform exponentiation using saferith
// 	// Convert to Nat for calculation
// 	baseNat := new(saferith.Nat).SetBytes(i.Abs().Bytes())
// 	exp := new(saferith.Nat).SetBytes(other.Abs().Bytes())
// 	result := new(saferith.Nat).SetUint64(1)

// 	// Simple exponentiation by repeated multiplication
// 	// Note: This is inefficient for large exponents
// 	expUint := exp.Uint64()
// 	for j := uint64(0); j < expUint; j++ {
// 		result = new(saferith.Nat).Mul(result, baseNat, -1)
// 	}

// 	// Convert back to Int, preserving sign
// 	resultInt := new(saferith.Int).SetNat(result)
// 	if i.IsNegative() && expUint%2 == 1 {
// 		// Negative base with odd exponent gives negative result
// 		resultInt.Neg(1)
// 	}

// 	return &Int{v: *resultInt}
// }

// func (i *unboundedTrait) IsInRange(modulus *NatPlus) bool {
// 	if modulus == nil {
// 		panic("argument is nil")
// 	}
// 	return i.v.CheckInRange(saferith.ModulusFromNat(&modulus.v)) == 1
// }

// func (i *unboundedTrait) Mod(modulus *NatPlus) *Uint {
// 	if modulus == nil {
// 		panic("argument is nil")
// 	}
// 	m := saferith.ModulusFromNat(&modulus.v)
// 	v := i.v.Mod(m)
// 	return &Uint{v: *v, m: m}
// }

// func (i *unboundedTrait) IsPositive() bool {
// 	// signMask is 1 if negative, 0 otherwise
// 	signMask := uint8(i.v.IsNegative()) // 1 if negative, 0 if non-negative

// 	// zeroMask is 1 if zero, 0 otherwise
// 	zeroMask := uint8(i.v.Eq(zeroInt))

// 	// ~signMask & ~zeroMask == 1 only if positive
// 	return ((^signMask & ^zeroMask) & 1) == 1
// }

// func (i *unboundedTrait) Coprime(other *Int) bool {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	return i.Abs().Coprime(other.Abs())
// }

// func (i *unboundedTrait) IsProbablyPrime() bool {
// 	return i.v.Big().ProbablyPrime(0)
// }

// func (i *unboundedTrait) EuclideanDiv(other *Int) (quot, rem *Int, err error) {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	q, r, err := i.Abs().EuclideanDiv(other.Abs())
// 	if err != nil {
// 		return nil, nil, errs.WrapFailed(err, "division failed")
// 	}
// 	if i.IsNegative() != other.IsNegative() {
// 		quot = q.Lift().Neg()
// 	} else {
// 		quot = q.Lift()
// 	}
// 	return quot, r.Lift(), nil
// }

// func (i *unboundedTrait) Abs() *Nat {
// 	return &Nat{v: *i.v.Abs()}
// }

// func (i *unboundedTrait) IsNegative() bool {
// 	return i.v.IsNegative() == 1
// }

// func (i *unboundedTrait) TryDiv(other *Int) (*Int, error) {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	quot, rem, err := i.EuclideanDiv(other)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "division failed")
// 	}
// 	if !rem.IsZero() {
// 		return nil, errs.NewValue("division not exact")
// 	}
// 	return quot, nil
// }

// func (i *unboundedTrait) TryInv() (*Int, error) {
// 	return nil, errs.NewValue("no multiplicative inverse for int")
// }

// func (i *unboundedTrait) TryNeg() (*Int, error) {
// 	return i.Neg(), nil
// }

// func (i *unboundedTrait) Neg() *Int {
// 	return &Int{v: *i.v.Clone().Neg(1)}
// }

// func (i *unboundedTrait) Double() *Int {
// 	return i.AddCap(i, i.v.AnnouncedLen()+1)
// }

// func (i *unboundedTrait) Square() *Int {
// 	return i.Mul(i)
// }

// func (i *unboundedTrait) Compare(other *Int) base.Ordering {
// 	if other == nil {
// 		panic("argument is nil")
// 	}

// 	// Equal case (constant-time Eq returns 1 for equality)
// 	if i.Equal(other) {
// 		return base.Equal
// 	}

// 	iAbs := i.Abs()
// 	oAbs := other.Abs()

// 	gt, eq, lt := iAbs.v.Cmp(&oAbs.v)

// 	// sign bits: 1 if negative, 0 if non-negative
// 	iNeg := int(i.v.IsNegative())
// 	oNeg := int(other.v.IsNegative())

// 	// Different signs: (iNeg, oNeg) → result
// 	// iNeg=1, oNeg=0 → LT
// 	// iNeg=0, oNeg=1 → GT
// 	// same sign → compare abs
// 	sameSign := 1 - (iNeg ^ oNeg)

// 	// If both negative, reverse abs compare
// 	reversed := iNeg & sameSign

// 	// Combine: use abs compare if sameSign == 1, otherwise use sign comparison
// 	// result = (1 - sameSign) * signComp + sameSign * (if reversed then reverse(absComp) else absComp)

// 	absComp := -1*int(lt) + 0*int(eq) + 1*int(gt)
// 	reversedComp := -1 * absComp

// 	signComp := -1*iNeg + 1*oNeg // if iNeg=1,oNeg=0 → -1; if iNeg=0,oNeg=1 → +1

// 	res := (1 - int(sameSign)) * signComp
// 	res += sameSign * ((1-reversed)*absComp + reversed*reversedComp)

// 	return base.Ordering(res)
// }

// func (i *unboundedTrait) IsLessThanOrEqual(other *Int) bool {
// 	return i.Compare(other) != base.GreaterThan
// }

// func (i *unboundedTrait) Equal(other *Int) bool {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	return i.v.Eq(&other.v) == 1
// }

// func (i *unboundedTrait) IsOpIdentity() bool {
// 	return i.IsZero()
// }

// func (i *unboundedTrait) ScalarOp(other *Int) *Int {
// 	return i.Mul(other)
// }

// func (i *unboundedTrait) IsTorsionFree() bool {
// 	return true
// }

// func (i *unboundedTrait) ScalarMul(other *Int) *Int {
// 	return i.Mul(other)
// }

// func (i *unboundedTrait) ScalarExp(other *Int) *Int {
// 	return i.Exp(other)
// }

// func (i *unboundedTrait) IsZero() bool {
// 	return i.v.Eq(new(saferith.Int).SetUint64(0)) == 1
// }

// func (i *unboundedTrait) IsOne() bool {
// 	return i.v.Eq(new(saferith.Int).SetUint64(1)) == 1
// }

// func (i *unboundedTrait) HashCode() base.HashCode {
// 	return base.HashCode(i.v.Abs().Uint64())
// }

// func (i *unboundedTrait) Clone() *Int {
// 	return &Int{v: *i.v.Clone()}
// }

// func (i *unboundedTrait) String() string {
// 	return saferith_utils.Stringer(&i.v)
// }

// func (i *unboundedTrait) Increment() *Int {
// 	return i.Add(Z().One())
// }

// func (i *unboundedTrait) Decrement() *Int {
// 	return i.Sub(Z().One())
// }

// func (i *unboundedTrait) Bytes() []byte {
// 	return i.v.Big().Bytes()
// }

// func (n *unboundedTrait) Bit(i int) uint8 {
// 	return uint8(n.v.Big().Bit(i))
// }

// func (n *unboundedTrait) IsEven() bool {
// 	return n.Bit(0) == 0
// }

// func (n *unboundedTrait) IsOdd() bool {
// 	return n.Bit(0) == 1
// }

// func (i *unboundedTrait) TrueLen() int {
// 	return i.v.TrueLen()
// }

// func (i *unboundedTrait) AnnouncedLen() int {
// 	return i.v.AnnouncedLen()
// }
