package num

// import (
// 	"io"
// 	"iter"
// 	"sync"

// 	"github.com/bronlabs/bron-crypto/pkg/base"
// 	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
// 	"github.com/bronlabs/bron-crypto/pkg/ase/nt/cardinal"
// 	"github.com/bronlabs/bron-crypto/pkg/base/errs"
// 	saferith_utils "github.com/bronlabs/bron-crypto/pkg/base/utils/saferith"
// 	"github.com/cronokirby/saferith"
// )

// var (
// 	_ algebra.ZLike[*Int]   = (*Integers)(nil)
// 	_ algebra.IntLike[*Int] = (*Int)(nil)

// 	_ algebra.AdditiveModule[*Int, *Int]        = (*Integers)(nil)
// 	_ algebra.AdditiveModuleElement[*Int, *Int] = (*Int)(nil)

// 	zeroInt = new(saferith.Int).SetUint64(0)
// 	oneInt  = new(saferith.Int).SetUint64(1)

// 	zOnce     sync.Once
// 	zInstance *Integers
// )

// func Z() *Integers {
// 	zOnce.Do(func() {
// 		zInstance = &Integers{}
// 	})
// 	return zInstance
// }

// type Integers struct{}

// func (*Integers) Name() string {
// 	return "Z"
// }

// func (*Integers) Order() cardinal.Cardinal {
// 	return cardinal.Infinite
// }

// func (*Integers) Characteristic() cardinal.Cardinal {
// 	return cardinal.Zero
// }

// func (zs *Integers) OpIdentity() *Int {
// 	return zs.Zero()
// }

// func (*Integers) Zero() *Int {
// 	return &Int{v: *zeroInt}
// }

// func (*Integers) One() *Int {
// 	return &Int{v: *oneInt}
// }

// func (*Integers) IsSemiDomain() bool {
// 	return true
// }

// func (*Integers) FromUint64(value uint64) *Int {
// 	out := new(saferith.Int).SetUint64(value)
// 	return &Int{v: *out}
// }

// func (*Integers) FromNat(value *Nat) (*Int, error) {
// 	if value == nil {
// 		return nil, errs.NewIsNil("value must not be nil")
// 	}
// 	out := new(saferith.Int).SetNat(&value.v)
// 	return &Int{v: *out}, nil
// }

// func (*Integers) FromInt64(value int64) *Int {
// 	var abs uint64
// 	if value < 0 {
// 		abs = uint64(-value)
// 	} else {
// 		abs = uint64(value)
// 	}
// 	v := new(saferith.Int).SetUint64(abs)
// 	out := &Int{v: *v}
// 	if value < 0 {
// 		out.v.Neg(1)
// 	}
// 	return out
// }

// func (zs *Integers) FromCardinal(value cardinal.Cardinal) (*Int, error) {
// 	n, err := N().FromCardinal(value)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "cannot convert cardinal to integer")
// 	}
// 	return zs.FromNat(n)
// }

// func (*Integers) FromBytes(input []byte) (*Int, error) {
// 	if input == nil {
// 		return nil, errs.NewIsNil("input must not be empty")
// 	}

// 	signed := new(saferith.Int).SetBytes(input)

// 	return &Int{v: *signed}, nil
// }

// func (*Integers) Random(lowInclusive, highExclusive *Int, prng io.Reader) (*Int, error) {
// 	out, err := saferith_utils.IntRandom(prng, &lowInclusive.v, &highExclusive.v)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return &Int{v: *out}, nil
// }

// func (zs *Integers) Iter() iter.Seq[*Int] {
// 	// Iterate integers alternating between positive and negative: 0, 1, -1, 2, -2, ...
// 	return func(yield func(*Int) bool) {
// 		// Start with 0
// 		if !yield(zs.Zero()) {
// 			return
// 		}

// 		// Then alternate between positive and negative
// 		for i := uint64(1); ; i++ {
// 			// Yield positive
// 			if !yield(zs.FromUint64(i)) {
// 				return
// 			}
// 			// Yield negative
// 			if !yield(zs.FromInt64(-int64(i))) {
// 				return
// 			}
// 		}
// 	}
// }

// func (*Integers) IterRange(start, stop *Int) iter.Seq[*Int] {
// 	if start == nil {
// 		return nil
// 	}
// 	cursor := start.Clone()
// 	var direction func(*Int) *Int
// 	if stop == nil {
// 		direction = func(i *Int) *Int { return i.Increment() }
// 		if start.IsNegative() {
// 			direction = func(i *Int) *Int { return i.Decrement() }
// 		}
// 		return func(yield func(*Int) bool) {
// 			for {
// 				if !yield(cursor) {
// 					return
// 				}
// 				cursor = direction(cursor)
// 			}
// 		}
// 	}
// 	// Empty range if start >= stop
// 	if start.Compare(stop) >= 0 {
// 		return func(yield func(*Int) bool) {}
// 	}
// 	return func(yield func(*Int) bool) {
// 		current := start.Clone()
// 		for current.Compare(stop) < 0 {
// 			if !yield(current) {
// 				return
// 			}
// 			current = current.Increment()
// 		}
// 	}
// }

// func (zs *Integers) MultiScalarOp(scs []*Int, es []*Int) (*Int, error) {
// 	return zs.MultiScalarMul(scs, es)
// }

// func (zs *Integers) MultiScalarMul(scs []*Int, es []*Int) (*Int, error) {
// 	if len(scs) != len(es) {
// 		return nil, errs.NewLength("scalars and exponents must have the same length")
// 	}
// 	// Empty slices should return zero
// 	if len(scs) == 0 {
// 		return zs.Zero(), nil
// 	}

// 	out := zs.Zero()
// 	for i, sc := range scs {
// 		if sc == nil || es[i] == nil {
// 			return nil, errs.NewIsNil("scalar or exponent is nil")
// 		}
// 		out = out.Add(sc.Mul(es[i]))
// 	}
// 	return out, nil
// }

// func (*Integers) ElementSize() int {
// 	return 0 // Int does not have a fixed size
// }

// func (*Integers) ScalarStructure() algebra.Structure[*Int] {
// 	return &Integers{}
// }

// type Int struct {
// 	v saferith.Int
// }

// func (i *Int) Structure() algebra.Structure[*Int] {
// 	return &Integers{}
// }

// func (i *Int) Op(other *Int) *Int {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	return i.Add(other)
// }

// func (i *Int) TryOpInv() (*Int, error) {
// 	return i.OpInv(), nil
// }

// func (i *Int) OpInv() *Int {
// 	return i.Neg()
// }

// func (i *Int) OtherOp(other *Int) *Int {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	return i.Mul(other)
// }

// func (i *Int) Add(other *Int) *Int {
// 	return i.AddCap(other, -1)
// }

// func (i *Int) AddCap(other *Int, cap int) *Int {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	out := new(saferith.Int).Add(&i.v, &other.v, cap)
// 	return &Int{v: *out}
// }

// func (i *Int) TrySub(other *Int) (*Int, error) {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	return i.Sub(other), nil
// }

// func (i *Int) Sub(other *Int) *Int {
// 	return i.SubCap(other, -1)
// }

// func (i *Int) SubCap(other *Int, cap int) *Int {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	return i.AddCap(other.Neg(), cap)
// }

// func (i *Int) Mul(other *Int) *Int {
// 	return i.MulCap(other, -1)
// }

// func (i *Int) MulCap(other *Int, cap int) *Int {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	out := new(saferith.Int).Mul(&i.v, &other.v, cap)
// 	return &Int{v: *out}
// }

// func (i *Int) Exp(other *Int) *Int {
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

// func (i *Int) IsInRange(modulus *NatPlus) bool {
// 	if modulus == nil {
// 		panic("argument is nil")
// 	}
// 	return i.v.CheckInRange(saferith.ModulusFromNat(&modulus.v)) == 1
// }

// func (i *Int) Mod(modulus *NatPlus) *Uint {
// 	if modulus == nil {
// 		panic("argument is nil")
// 	}
// 	m := saferith.ModulusFromNat(&modulus.v)
// 	v := i.v.Mod(m)
// 	return &Uint{v: *v, m: m}
// }

// func (i *Int) IsPositive() bool {
// 	// signMask is 1 if negative, 0 otherwise
// 	signMask := uint8(i.v.IsNegative()) // 1 if negative, 0 if non-negative

// 	// zeroMask is 1 if zero, 0 otherwise
// 	zeroMask := uint8(i.v.Eq(zeroInt))

// 	// ~signMask & ~zeroMask == 1 only if positive
// 	return ((^signMask & ^zeroMask) & 1) == 1
// }

// func (i *Int) Coprime(other *Int) bool {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	return i.Abs().Coprime(other.Abs())
// }

// func (i *Int) IsProbablyPrime() bool {
// 	return i.v.Big().ProbablyPrime(0)
// }

// func (i *Int) EuclideanDiv(other *Int) (quot, rem *Int, err error) {
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

// func (i *Int) Abs() *Nat {
// 	return &Nat{v: *i.v.Abs()}
// }

// func (i *Int) IsNegative() bool {
// 	return i.v.IsNegative() == 1
// }

// func (i *Int) TryDiv(other *Int) (*Int, error) {
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

// func (i *Int) TryInv() (*Int, error) {
// 	return nil, errs.NewValue("no multiplicative inverse for int")
// }

// func (i *Int) TryNeg() (*Int, error) {
// 	return i.Neg(), nil
// }

// func (i *Int) Neg() *Int {
// 	return &Int{v: *i.v.Clone().Neg(1)}
// }

// func (i *Int) Double() *Int {
// 	return i.AddCap(i, i.v.AnnouncedLen()+1)
// }

// func (i *Int) Square() *Int {
// 	return i.Mul(i)
// }

// func (i *Int) Compare(other *Int) base.Ordering {
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

// func (i *Int) IsLessThanOrEqual(other *Int) bool {
// 	return i.Compare(other) != base.GreaterThan
// }

// func (i *Int) Equal(other *Int) bool {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	return i.v.Eq(&other.v) == 1
// }

// func (i *Int) IsOpIdentity() bool {
// 	return i.IsZero()
// }

// func (i *Int) ScalarOp(other *Int) *Int {
// 	return i.Mul(other)
// }

// func (i *Int) IsTorsionFree() bool {
// 	return true
// }

// func (i *Int) ScalarMul(other *Int) *Int {
// 	return i.Mul(other)
// }

// func (i *Int) ScalarExp(other *Int) *Int {
// 	return i.Exp(other)
// }

// func (i *Int) IsZero() bool {
// 	return i.v.Eq(new(saferith.Int).SetUint64(0)) == 1
// }

// func (i *Int) IsOne() bool {
// 	return i.v.Eq(new(saferith.Int).SetUint64(1)) == 1
// }

// func (i *Int) HashCode() base.HashCode {
// 	return base.HashCode(i.v.Abs().Uint64())
// }

// func (i *Int) Clone() *Int {
// 	return &Int{v: *i.v.Clone()}
// }

// func (i *Int) String() string {
// 	return saferith_utils.Stringer(&i.v)
// }

// func (i *Int) Increment() *Int {
// 	return i.Add(Z().One())
// }

// func (i *Int) Decrement() *Int {
// 	return i.Sub(Z().One())
// }

// func (i *Int) Bytes() []byte {
// 	return i.v.Big().Bytes()
// }

// func (n *Int) Bit(i int) uint8 {
// 	return uint8(n.v.Big().Bit(i))
// }

// func (n *Int) IsEven() bool {
// 	return n.Bit(0) == 0
// }

// func (n *Int) IsOdd() bool {
// 	return n.Bit(0) == 1
// }

// func (i *Int) TrueLen() int {
// 	return i.v.TrueLen()
// }

// func (i *Int) AnnouncedLen() int {
// 	return i.v.AnnouncedLen()
// }
