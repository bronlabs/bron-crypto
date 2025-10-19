package num

import (
	"io"
	"iter"
	"math/big"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

var (
	// _ internal.Z[*Int, *NatPlus, *Nat, *Int, *Uint]   = (*Integers)(nil)
	// _ internal.Int[*Int, *NatPlus, *Nat, *Int, *Uint] = (*Int)(nil).

	zOnce     sync.Once
	zInstance *Integers
)

func Z() *Integers {
	zOnce.Do(func() {
		zInstance = &Integers{}
	})
	return zInstance
}

type Integers struct{}

func (*Integers) Name() string {
	return "Z"
}

func (*Integers) Order() cardinal.Cardinal {
	return cardinal.Infinite()
}

func (*Integers) Characteristic() cardinal.Cardinal {
	return cardinal.Zero()
}

func (zs *Integers) OpIdentity() *Int {
	return zs.Zero()
}

func (*Integers) Zero() *Int {
	return &Int{v: numct.IntZero()}
}

func (*Integers) One() *Int {
	return &Int{v: numct.IntOne()}
}

func (*Integers) IsSemiDomain() bool {
	return true
}

func (*Integers) FromUint64(value uint64) *Int {
	return &Int{v: numct.NewIntFromUint64(value)}
}

func (zs *Integers) FromBig(value *big.Int) (*Int, error) {
	if value == nil {
		return nil, errs.NewIsNil("value must not be nil")
	}
	return zs.FromBytes(value.Bytes())
}

func (*Integers) FromNatPlus(value *NatPlus) (*Int, error) {
	if value == nil {
		return nil, errs.NewIsNil("value must not be nil")
	}
	return &Int{v: numct.NewIntFromBytes(value.Bytes())}, nil
}

func (*Integers) FromNat(value *Nat) (*Int, error) {
	if value == nil {
		return nil, errs.NewIsNil("value must not be nil")
	}
	return &Int{v: numct.NewIntFromBytes(value.Bytes())}, nil
}

func (*Integers) FromNatCT(value *numct.Nat) (*Int, error) {
	if value == nil {
		return nil, errs.NewIsNil("value must not be nil")
	}
	return &Int{v: numct.NewIntFromBytes(value.Bytes())}, nil
}

func (*Integers) FromIntCT(value *numct.Int) (*Int, error) {
	if value == nil {
		return nil, errs.NewIsNil("value must not be nil")
	}
	return &Int{v: value.Clone()}, nil
}

func (*Integers) FromInt64(value int64) *Int {
	return &Int{v: numct.NewInt(value)}
}

func (zs *Integers) FromCardinal(value cardinal.Cardinal) (*Int, error) {
	n, err := N().FromCardinal(value)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot convert cardinal to integer")
	}
	return zs.FromNat(n)
}

func (*Integers) FromBytes(input []byte) (*Int, error) {
	if input == nil {
		return nil, errs.NewIsNil("input must not be empty")
	}

	return &Int{v: numct.NewIntFromBytes(input)}, nil
}

func (*Integers) FromUint(input *Uint) (*Int, error) {
	if input == nil {
		return nil, errs.NewIsNil("input must not be nil")
	}
	return &Int{v: numct.NewIntFromBytes(input.Bytes())}, nil
}

func (*Integers) FromUintSymmetric(input *Uint) (*Int, error) {
	if input == nil {
		return nil, errs.NewIsNil("input must not be nil")
	}
	var v numct.Int
	input.m.ModSymmetric(&v, input.v)
	return &Int{v: &v}, nil
}

func (*Integers) Random(lowInclusive, highExclusive *Int, prng io.Reader) (*Int, error) {
	if prng == nil || lowInclusive == nil || highExclusive == nil {
		return nil, errs.NewIsNil("prng is nil or lowInclusive is nil or highExclusive is nil")
	}
	v, err := numct.IntRandom(prng, lowInclusive.v, highExclusive.v)
	if err != nil {
		return nil, err
	}
	return &Int{v: v}, nil
}

func (zs *Integers) Iter() iter.Seq[*Int] {
	// Iterate integers alternating between positive and negative: 0, 1, -1, 2, -2, ...
	return func(yield func(*Int) bool) {
		// Start with 0
		if !yield(zs.Zero()) {
			return
		}

		current := zs.One()
		// Then alternate between positive and negative
		for {
			// Yield positive
			if !yield(current) {
				return
			}
			// Yield negative
			if !yield(current.Neg()) {
				return
			}
			current = current.Increment()
		}
	}
}

func (*Integers) IterRange(start, stop *Int) iter.Seq[*Int] {
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
	// Empty range if start >= stop
	if start.Compare(stop) >= 0 {
		return func(yield func(*Int) bool) {}
	}
	return func(yield func(*Int) bool) {
		current := start.Clone()
		for current.Compare(stop) < 0 {
			if !yield(current) {
				return
			}
			current = current.Increment()
		}
	}
}

func (zs *Integers) MultiScalarOp(scs []*Int, es []*Int) (*Int, error) {
	return zs.MultiScalarMul(scs, es)
}

func (zs *Integers) MultiScalarMul(scs []*Int, es []*Int) (*Int, error) {
	if len(scs) != len(es) {
		return nil, errs.NewLength("scalars and exponents must have the same length")
	}
	// Empty slices should return zero
	if len(scs) == 0 {
		return zs.Zero(), nil
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

func (*Integers) ElementSize() int {
	return 0 // Int does not have a fixed size
}

func (*Integers) ScalarStructure() algebra.Structure[*Int] {
	return Z()
}

type Int struct {
	v *numct.Int
}

func (i *Int) Value() *numct.Int {
	return i.v
}

func (*Int) isValid(x *Int) (*Int, error) {
	if x == nil {
		return nil, errs.NewValue("argument is nil")
	}
	return x, nil
}

func (*Int) ensureValid(x *Int) *Int {
	// TODO: fix err package
	x, err := x.isValid(x)
	if err != nil {
		panic(err)
	}
	return x
}

func (i *Int) Structure() algebra.Structure[*Int] {
	return Z()
}

func (i *Int) Op(other *Int) *Int {
	return i.Add(other)
}

func (i *Int) TryOpInv() (*Int, error) {
	return i.OpInv(), nil
}

func (i *Int) OpInv() *Int {
	return i.Neg()
}

func (i *Int) OtherOp(other *Int) *Int {
	return i.Mul(other)
}

func (i *Int) Add(other *Int) *Int {
	i.ensureValid(other)
	v := new(numct.Int)
	v.Add(i.v, other.v)
	return &Int{v: v}
}

func (i *Int) TrySub(other *Int) (*Int, error) {
	return i.Sub(other), nil
}

func (i *Int) Sub(other *Int) *Int {
	i.ensureValid(other)
	v := new(numct.Int)
	v.Sub(i.v, other.v)
	return &Int{v: v}
}

func (i *Int) Mul(other *Int) *Int {
	i.ensureValid(other)
	v := new(numct.Int)
	v.Mul(i.v, other.v)
	return &Int{v: v}
}

func (i *Int) Lsh(shift uint) *Int {
	v := new(numct.Int)
	v.Lsh(i.v, shift)
	return &Int{v: v}
}

func (i *Int) Rsh(shift uint) *Int {
	v := new(numct.Int)
	v.Rsh(i.v, shift)
	return &Int{v: v}
}

func (i *Int) IsInRange(modulus *NatPlus) bool {
	if modulus == nil {
		panic("argument is nil")
	}
	return modulus.ModulusCT().IsInRange(i.Abs().v) == ct.True
}

func (i *Int) Mod(modulus *NatPlus) *Uint {
	out := new(numct.Nat)
	modulus.ModulusCT().ModInt(out, i.v)
	return &Uint{v: out, m: modulus.ModulusCT()}

	// if modulus == nil {
	// 	panic("modulus is nil")
	// }
	// // For proper modular arithmetic, we need to ensure the result is in [0, modulus)
	// // If i is negative, we need to add modulus repeatedly until positive
	// m, ok := numct.NewModulus(modulus.v)
	// if ok == ct.False {
	// 	panic(errs.NewFailed("modulus is not valid"))
	// }

	// // Convert to Nat, handling negative values properly
	// result := new(numct.Nat)
	// absVal := i.Abs() // This returns *Nat
	// remainder := new(numct.Nat)
	// // Mod operation is already available through the modulus m created above
	// m.Mod(remainder, absVal.v)

	// if i.IsNegative() {
	// 	// For negative numbers, if remainder is non-zero, we need modulus - remainder
	// 	// Otherwise result is 0
	// 	isZero := remainder.IsZero()
	// 	if isZero == ct.False {
	// 		// Compute modulus - remainder
	// 		m.ModSub(result, modulus.v, remainder)
	// 	} else {
	// 		result.Set(remainder) // which is 0
	// 	}
	// } else {
	// 	// For positive numbers, just use the remainder
	// 	result.Set(remainder)
	// }

	// return &Uint{v: result, m: m}
}

func (i *Int) IsPositive() bool {
	return i.v.IsNegative()|i.v.IsZero() == ct.False
}

func (i *Int) Coprime(other *Int) bool {
	i.ensureValid(other)
	return i.v.Coprime(other.v) == ct.True
}

func (i *Int) IsProbablyPrime() bool {
	return i.v.IsProbablyPrime() == ct.True
}

func (i *Int) EuclideanDiv(other *Int) (quot, rem *Int, err error) {
	i.ensureValid(other)
	vq, vr := new(numct.Int), new(numct.Int)
	// Since DivModCap doesn't exist for Int, compute quotient and remainder separately
	if ok := vq.Div(i.v, other.v); ok == ct.False {
		return nil, nil, errs.NewFailed("division failed")
	}

	// Compute remainder: rem = i - other * quot
	temp := new(numct.Int)
	temp.Mul(other.v, vq)
	vr.Sub(i.v, temp)
	return &Int{v: vq}, &Int{v: vr}, nil
}

func (i *Int) EuclideanValuation() *Int {
	return i.Abs().Lift()
}

func (i *Int) Abs() *Nat {
	return &Nat{v: (*numct.Nat)((*saferith.Int)(i.v.Clone()).Abs())}
}

func (i *Int) IsNegative() bool {
	return i.v.IsNegative() == ct.True
}

func (i *Int) IsUnit(modulus *NatPlus) bool {
	if modulus == nil {
		panic("argument is nil")
	}
	m, ok := numct.NewModulus(modulus.v)
	if ok == ct.False {
		panic(errs.NewFailed("modulus is not valid"))
	}
	return m.IsUnit(i.Mod(modulus).v) == ct.True
}

func (i *Int) TryDiv(other *Int) (*Int, error) {
	if _, err := i.isValid(other); err != nil {
		return nil, errs.WrapFailed(err, "argument is not valid")
	}
	// First check if division would be exact
	quotient, remainder, err := i.EuclideanDiv(other)
	if err != nil {
		return nil, err
	}
	// Check if remainder is zero (exact division)
	if !remainder.IsZero() {
		return nil, errs.NewFailed("division is not exact")
	}
	return quotient, nil
}

func (i *Int) TryInv() (*Int, error) {
	return nil, errs.NewValue("no multiplicative inverse for int")
}

func (i *Int) TryNeg() (*Int, error) {
	return i.Neg(), nil
}

func (i *Int) Neg() *Int {
	v := new(numct.Int)
	v.Neg(i.v.Clone())
	return &Int{v: v}
}

func (i *Int) Double() *Int {
	return i.Add(i)
}

func (i *Int) Square() *Int {
	return i.Mul(i)
}

func (i *Int) Compare(other *Int) base.Ordering {
	i.ensureValid(other)
	lt, eq, gt := i.v.Compare(other.v)
	return base.Ordering(-1*int(lt) + 0*int(eq) + 1*int(gt))
}

func (i *Int) IsLessThanOrEqual(other *Int) bool {
	i.ensureValid(other)
	lt, eq, _ := i.v.Compare(other.v)
	return lt|eq == ct.True
}

func (i *Int) Equal(other *Int) bool {
	i.ensureValid(other)
	return i.v.Equal(other.v) == ct.True
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

func (i *Int) IsZero() bool {
	return i.v.IsZero() == ct.True
}

func (i *Int) IsOne() bool {
	return i.v.IsOne() == ct.True
}

func (i *Int) HashCode() base.HashCode {
	return i.v.HashCode()
}

func (i *Int) Clone() *Int {
	return &Int{v: i.v.Clone()}
}

func (i *Int) String() string {
	return i.v.Big().String()
}

func (i *Int) Increment() *Int {
	return i.Add(Z().One())
}

func (i *Int) Decrement() *Int {
	return i.Sub(Z().One())
}

func (i *Int) Bytes() []byte {
	// Use Big().Bytes() to get compact representation without padding
	bytes := i.v.Big().Bytes()
	// big.Int.Bytes() returns empty slice for zero, but we want [0x0]
	if len(bytes) == 0 {
		return []byte{0x0}
	}
	return bytes
}

func (n *Int) Bit(i uint) byte {
	return (n.v.Bit(i))
}

func (n *Int) IsEven() bool {
	return n.v.IsEven() == ct.True
}

func (n *Int) IsOdd() bool {
	return n.v.IsOdd() == ct.True
}

func (i *Int) Big() *big.Int {
	return i.v.Big()
}

func (i *Int) Lift() *Int {
	return i.Clone()
}

func (i *Int) Cardinal() cardinal.Cardinal {
	return cardinal.NewFromSaferith((*saferith.Nat)(i.Abs().v))
}

func (i *Int) TrueLen() uint {
	return i.v.TrueLen()
}

func (i *Int) AnnouncedLen() uint {
	return i.v.AnnouncedLen()
}
