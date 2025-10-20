package numct

import (
	"math/big"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/internal"
)

var (
	_ (internal.IntMutable[*Int, Modulus]) = (*Int)(nil)
)

func IntOne() *Int {
	return (*Int)(new(saferith.Int).SetUint64(1).Resize(1))
}

func IntZero() *Int {
	return (*Int)(new(saferith.Int).SetUint64(0).Resize(1))
}

func NewInt(value int64) *Int {
	n := new(Int)
	n.SetInt64(value)
	return n
}

func NewIntFromUint64(value uint64) *Int {
	n := new(Int)
	n.SetUint64(value)
	return n
}

func NewIntFromSaferith(n *saferith.Int) *Int {
	return (*Int)(n)
}

func NewIntFromBytes(n []byte) *Int {
	return (*Int)(new(saferith.Int).SetBytes(n))
}

func NewIntFromBig(n *big.Int, cap int) *Int {
	return (*Int)(new(saferith.Int).SetBig(n, cap))
}

type Int saferith.Int

func (i *Int) Abs() {
	(*saferith.Int)(i).Neg(saferith.Choice(i.IsNegative()))
}

func (i *Int) abs() *Nat {
	return (*Nat)((*saferith.Int)(i).Abs())
}

func (i *Int) Set(v *Int) {
	*i = *v
}

func (i *Int) SetNat(v *Nat) {
	i.Set((*Int)(new(saferith.Int).SetNat((*saferith.Nat)(v))))
}

func (i *Int) Clone() *Int {
	return (*Int)((*saferith.Int)(i).Clone())
}

func (i *Int) SetZero() {
	i.Set(IntZero())
}

func (i *Int) SetOne() {
	i.Set(IntOne())
}

func (i *Int) Add(lhs, rhs *Int) {
	i.AddCap(lhs, rhs, -1)
}

func (i *Int) AddCap(lhs, rhs *Int, cap int) {
	(*saferith.Int)(i).Add((*saferith.Int)(lhs), (*saferith.Int)(rhs), cap)
}

func (i *Int) Neg(x *Int) {
	i.Set((*Int)((*saferith.Int)(x.Clone()).Neg(saferith.Choice(1))))
}

func (i *Int) Sub(lhs, rhs *Int) {
	i.SubCap(lhs, rhs, -1)
}

func (i *Int) SubCap(lhs, rhs *Int, cap int) {
	rhsNeg := rhs.Clone()
	rhsNeg.Neg(rhs)
	i.AddCap(lhs, rhsNeg, cap)
}

func (i *Int) Mul(lhs, rhs *Int) {
	i.MulCap(lhs, rhs, -1)
}

func (i *Int) MulCap(lhs, rhs *Int, cap int) {
	(*saferith.Int)(i).Mul((*saferith.Int)(lhs), (*saferith.Int)(rhs), cap)
}

func (i *Int) Div(numerator, denominator *Int) (ok ct.Bool) {
	dm, ok := NewModulus(denominator.abs())
	if ok == ct.False {
		return ct.False
	}
	ok = i.DivCap(numerator, dm, -1)
	// Adjust sign: result is negative if signs differ
	shouldNegate := numerator.IsNegative() ^ denominator.IsNegative()
	i.CondNeg(ct.Choice(shouldNegate))
	return ok
}

func (i *Int) DivCap(numerator *Int, denominator Modulus, cap int) (ok ct.Bool) {
	var outNat Nat
	ok = outNat.DivCap(numerator.abs(), denominator, cap)

	i.SetNat(&outNat)
	// Result is already positive from DivCap on absolute values
	// Caller is responsible for adjusting sign if needed
	return ok
}

func (i *Int) ExactDiv(lhs *Int, rhs Modulus) (ok ct.Bool) {
	var outNat Nat
	ok = outNat.ExactDiv(lhs.abs(), rhs)
	i.SetNat(&outNat)
	i.CondNeg(lhs.IsNegative())
	return ok
}

func (i *Int) Inv(x *Int) (ok ct.Bool) {
	return ct.False
}

func (i *Int) Double(x *Int) {
	i.Add(x, x)
}

func (i *Int) IsNegative() ct.Bool {
	return ct.Bool((*saferith.Int)(i).IsNegative())
}

func (i *Int) IsZero() ct.Bool {
	return i.abs().IsZero()
}

func (i *Int) IsNonZero() ct.Bool {
	return i.IsZero().Not()
}

func (i *Int) IsOne() ct.Bool {
	return i.Equal(IntOne())
}

func (i *Int) Sqrt(x *Int) (ok ct.Bool) {
	// Constant-time (w.r.t. announced capacity) integer square root.
	// Work on |x| and assign only if |x| is a perfect square.

	// Negative numbers are never perfect squares in Z.
	nonNeg := x.IsNegative().Not()

	// Magnitude and (public) capacity.
	a := x.abs()
	capBits := int(a.AnnouncedLen())

	var rootNat saferith.Nat
	var okRes ct.Bool

	// ===== Single-limb fast path (<= 64 bits): 32 fixed rounds, branchless. =====
	if capBits <= 64 {
		u0 := a.Uint64()
		r64 := ct.Isqrt64(u0)
		rootNat.SetUint64(r64).Resize(capBits)

		// Exactness check: r64^2 fits in uint64 because r64 <= 2^32.
		sq := r64 * r64
		okRes = ct.Bool(ct.Equal(sq, u0))
	} else {
		// ===== Multi-limb path: restoring (digit-by-digit) method. =====
		// Runtime depends only on capBits (pairs), not on the value.
		var n saferith.Nat // remainder
		n.SetNat((*saferith.Nat)(a))
		n.Resize(capBits)

		var y saferith.Nat // accumulating root
		y.SetUint64(0)
		y.Resize(capBits)

		pairs := (capBits + 1) / 2 // number of two-bit groups to process

		// b := 1 << startEven, where startEven is the top even bit < capBits
		var b saferith.Nat
		b.SetUint64(1)
		if pairs > 0 {
			startEven := 2 * (pairs - 1)
			b.Lsh(&b, uint(startEven), capBits)
		} else {
			b.Resize(capBits)
		}

		// Scratch (BoringSSL-style reuse).
		var m saferith.Nat      // y + b
		var yshr saferith.Nat   // y >> 1
		var nMinus saferith.Nat // n - m
		var yPlus saferith.Nat  // (y>>1) + b
		var bshr saferith.Nat   // b >> 2

		for range pairs {
			// m = y + b
			m.Add(&y, &b, int(capBits))

			// yshr = y >> 1 (computed unconditionally)
			yshr.Rsh(&y, 1, int(capBits))

			// Candidates (computed unconditionally)
			nMinus.Sub(&n, &m, int(capBits))   // n - m
			yPlus.Add(&yshr, &b, int(capBits)) // (y>>1) + b

			// ge := (n >= m) in constant time.
			gt, eq, _ := n.Cmp(&m)
			ge := gt | eq

			// Apply updates branchlessly.
			n.CondAssign(ge, &nMinus)
			y = yshr
			y.CondAssign(ge, &yPlus)

			// b >>= 2
			bshr.Rsh(&b, 2, int(capBits))
			b = bshr
		}

		// ok iff remainder is zero.
		var z saferith.Nat
		z.Resize(capBits)
		_, eqZero, _ := n.Cmp(&z)
		okRes = ct.Bool(eqZero)

		rootNat.SetNat(&y)
	}

	ok = okRes & nonNeg

	// Conditionally assign the root.
	var root Int
	(*saferith.Int)(&root).SetNat(&rootNat)
	i.Select(ok, i, &root)
	return ok
}

func (i *Int) Square(x *Int) {
	i.Mul(x, x)
}

func (i *Int) Bit(index uint) byte {
	return i.abs().Bit(index)
}

func (i *Int) Bytes() []byte {
	return i.abs().Bytes()
}

func (i *Int) SetBytes(b []byte) (ok ct.Bool) {
	(*saferith.Int)(i).SetBytes(b)
	return ct.True
}

func (i *Int) Increment() {
	i.Add(i, IntOne())
}

func (i *Int) Decrement() {
	i.Sub(i, IntOne())
}

func (i *Int) Lsh(x *Int, shift uint) {
	i.LshCap(x, shift, -1)
}

func (i *Int) LshCap(x *Int, shift uint, cap int) {
	out := i.abs()
	out.LshCap(x.abs(), shift, cap)
	i.SetNat(out)
	// Preserve sign
	(*saferith.Int)(i).Neg(saferith.Choice(x.IsNegative()))
}

func (i *Int) Rsh(x *Int, shift uint) {
	i.RshCap(x, shift, -1)
}

func (i *Int) RshCap(x *Int, shift uint, cap int) {
	out := i.abs()
	out.RshCap(x.abs(), shift, cap)
	i.SetNat(out)
	// Preserve sign
	(*saferith.Int)(i).Neg(saferith.Choice(x.IsNegative()))
}

func (i *Int) Resize(cap int) {
	// When cap < 0, use the current announced length
	// When cap >= 0, use the provided cap
	// CSelectInt(choice, x0, x1): returns x0 when choice=0, x1 when choice=1
	// GreaterOrEqual(cap, 0): returns 1 when cap >= 0
	// So: when cap >= 0 (choice=1), select cap (x1)
	//     when cap < 0 (choice=0), select announcedLen (x0)
	effectiveCap := ct.CSelectInt(ct.GreaterOrEqual(cap, 0), int(i.AnnouncedLen()), cap)
	(*saferith.Int)(i).Resize(effectiveCap)
}

func (i *Int) Coprime(rhs *Int) ct.Bool {
	return i.abs().Coprime(rhs.abs())
}

func (i *Int) IsProbablyPrime() ct.Bool {
	return i.abs().IsProbablyPrime() & i.IsNegative().Not()
}

func (i *Int) Select(choice ct.Choice, x0, x1 *Int) {
	// Select should set i = choice ? x1 : x0
	// Since saferith.Int doesn't have Select, we need to implement it ourselves

	// Get absolute values
	abs0 := x0.abs()
	abs1 := x1.abs()

	// Use Nat's Select for the magnitude
	var selectedAbs Nat
	selectedAbs.Set(abs0)
	selectedAbs.Select(choice, &selectedAbs, abs1)

	// Select the sign
	selectedNeg := ct.CSelectInt(choice, x0.IsNegative(), x1.IsNegative())

	// Set the result
	i.SetNat(&selectedAbs)
	(*saferith.Int)(i).Neg(saferith.Choice(selectedNeg))
}

func (i *Int) CondAssign(choice ct.Choice, x *Int) {
	// Save i's original sign before modifying
	iNeg := i.IsNegative()

	// Conditionally assign magnitude
	outNat := i.abs()
	outNat.CondAssign(choice, x.abs())
	i.SetNat(outNat) // Now i is positive with conditionally updated magnitude

	// Conditionally set sign: use i's original sign when choice=0, x's sign when choice=1
	finalSign := ct.CSelectInt(choice, iNeg, x.IsNegative())
	i.CondNeg(finalSign)
}

func (i *Int) CondNeg(choice ct.Choice) {
	(*saferith.Int)(i).Neg(saferith.Choice(choice))
}

func (i *Int) Equal(rhs *Int) ct.Bool {
	return ct.Bool((*saferith.Int)(i).Eq((*saferith.Int)(rhs)))
}

func (i *Int) Compare(rhs *Int) (lt, eq, gt ct.Bool) {
	// Signs as ct.Bool (0/1)
	aNeg := i.IsNegative()
	bNeg := rhs.IsNegative()

	// Magnitude compare on |i| and |rhs|
	ltM, eqM, gtM := i.abs().Compare(rhs.abs())

	// same = 1 iff signs are equal
	same := (aNeg ^ bNeg).Not()
	// bothNeg = 1 iff both are negative
	bothNeg := same & aNeg

	// If both negative, reverse magnitude ordering
	ltSame := ct.CSelectInt(bothNeg, ltM, gtM) // when bothNeg==0 pick ltM, when bothNeg==1 pick gtM
	gtSame := ct.CSelectInt(bothNeg, gtM, ltM) // when bothNeg==0 pick gtM, when bothNeg==1 pick ltM

	// Only use magnitude comparison when signs are the same
	ltSame = same & ltSame
	gtSame = same & gtSame
	eqSame := same & eqM

	// Different signs: negative < non-negative
	ltDiff := aNeg & (bNeg ^ 1) // a neg, b non-neg
	gtDiff := (aNeg ^ 1) & bNeg // a non-neg, b neg

	lt = ltSame | ltDiff
	gt = gtSame | gtDiff
	eq = eqSame
	return
}

func (i *Int) Uint64() uint64 {
	return i.abs().Uint64()
}

func (i *Int) SetUint64(x uint64) {
	(*saferith.Int)(i).SetUint64(x)
}

func (i *Int) Int64() int64 {
	abs := int64(i.abs().Uint64())
	negated := abs * -1
	// When IsNegative() is 1 (true), select negated
	// ct.Select returns x1 when choice is 1, x0 when choice is 0
	return ct.CSelectInt(i.IsNegative(), abs, negated)
}

func (i *Int) SetInt64(x int64) {
	ux := uint64(x)

	// s is all 1s (0xFFFF..FFFF) if x < 0, else 0.
	s := uint64(int64(x) >> 63)

	// mag = |x| as uint64, computed without branches and safe for MinInt64.
	// For x >= 0: (ux ^ 0) - 0 = ux
	// For x < 0 : (ux ^ s) - s = (~ux) + 1  == two's-complement abs(x)
	mag := (ux ^ s) - s

	// Set magnitude, then apply sign in constant time.
	(*saferith.Int)(i).SetUint64(mag)

	// Negate iff x < 0. (ux>>63) is 1 for negative x, 0 otherwise.
	(*saferith.Int)(i).Neg(saferith.Choice((ux >> 63) & 1))
}

func (i *Int) TrueLen() uint {
	return uint((*saferith.Int)(i).TrueLen())
}

func (i *Int) AnnouncedLen() uint {
	return uint((*saferith.Int)(i).AnnouncedLen())
}

func (i *Int) IsOdd() ct.Bool {
	return i.abs().IsOdd()
}

func (i *Int) IsEven() ct.Bool {
	return i.IsOdd().Not()
}

func (i *Int) String() string {
	return (*saferith.Int)(i).String()
}

func (i *Int) HashCode() base.HashCode {
	return base.DeriveHashCode(i.Bytes())
}

func (i *Int) Big() *big.Int {
	return (*saferith.Int)(i).Big()
}

// And sets i = x & y and returns i.
// For signed integers, this operates on the two's complement representation.
func (i *Int) And(x, y *Int) {
	i.AndCap(x, y, -1)
}

// AndCap sets i = x & y with capacity cap and returns i.
// For signed integers, this operates on the two's complement representation.
func (i *Int) AndCap(x, y *Int, cap int) {
	// Two's complement AND logic:
	// pos & pos = pos (magnitude AND)
	// pos & neg = pos & ~(|neg|-1) = pos - (pos & (|neg|-1))
	// neg & pos = ~(|neg|-1) & pos = pos - (pos & (|neg|-1))
	// neg & neg = -((|x|-1) | (|y|-1) + 1)

	xNeg := x.IsNegative()
	yNeg := y.IsNegative()
	xAbs := x.abs()
	yAbs := y.abs()

	// Calculate all four cases
	bothPos := (xNeg | yNeg).Not()
	bothNeg := xNeg & yNeg
	xNegYPos := xNeg & yNeg.Not()
	xPosYNeg := xNeg.Not() & yNeg

	// Case 1: Both positive - simple AND
	case1 := new(Nat)
	case1.AndCap(xAbs, yAbs, cap)

	// Case 2: x negative, y positive
	// result = y - (y & (|x|-1))
	xAbsMinus1 := new(Nat)
	xAbsMinus1.Set(xAbs)
	xAbsMinus1.Decrement() // Safe because |x| > 0 for negative x

	yAndXMinus1 := new(Nat)
	yAndXMinus1.And(yAbs, xAbsMinus1)
	case2 := new(Nat)
	case2.SubCap(yAbs, yAndXMinus1, cap)

	// Case 3: x positive, y negative
	// result = x - (x & (|y|-1))
	yAbsMinus1 := new(Nat)
	yAbsMinus1.Set(yAbs)
	yAbsMinus1.Decrement() // Safe because |y| > 0 for negative y

	xAndYMinus1 := new(Nat)
	xAndYMinus1.And(xAbs, yAbsMinus1)
	case3 := new(Nat)
	case3.SubCap(xAbs, xAndYMinus1, cap)

	// Case 4: Both negative
	// result = -((|x|-1) | (|y|-1) + 1)
	orResult := new(Nat)
	orResult.Or(xAbsMinus1, yAbsMinus1)
	orResult.Increment()

	// Select the appropriate result using constant-time selection
	resultMag := new(Nat)
	resultMag.SetZero()
	resultMag.CondAssign(bothPos, case1)
	resultMag.CondAssign(xNegYPos, case2)
	resultMag.CondAssign(xPosYNeg, case3)
	resultMag.CondAssign(bothNeg, orResult)

	// Set the result with appropriate sign
	i.SetNat(resultMag)
	i.CondNeg(bothNeg)
	if cap >= 0 {
		i.Resize(cap)
	}
}

// Or sets i = x | y and returns i.
// For signed integers, this operates on the two's complement representation.
func (i *Int) Or(x, y *Int) {
	i.OrCap(x, y, -1)
}

// OrCap sets i = x | y with capacity cap and returns i.
// For signed integers, this operates on the two's complement representation.
func (i *Int) OrCap(x, y *Int, cap int) {
	// Two's complement OR logic:
	// pos | pos = pos (magnitude OR)
	// pos | neg = ~((|neg|-1) & ~pos) = -(((|neg|-1) & ~pos) + 1)
	// neg | pos = ~(~pos & (|neg|-1)) = -(((|neg|-1) & ~pos) + 1)
	// neg | neg = -((|x|-1) & (|y|-1) + 1)

	xNeg := x.IsNegative()
	yNeg := y.IsNegative()
	xAbs := x.abs()
	yAbs := y.abs()

	// Calculate all four cases
	bothPos := (xNeg | yNeg).Not()
	bothNeg := xNeg & yNeg
	xNegYPos := xNeg & yNeg.Not()
	xPosYNeg := xNeg.Not() & yNeg

	// Case 1: Both positive - simple OR
	case1 := new(Nat)
	case1.OrCap(xAbs, yAbs, cap)

	// Case 2: x negative, y positive
	// result = -((|x|-1) & ~y + 1)
	xAbsMinus1 := new(Nat)
	xAbsMinus1.Set(xAbs)
	xAbsMinus1.Decrement()

	yNot := new(Nat)
	yNot.NotCap(yAbs, int(yAbs.AnnouncedLen()))

	case2Mag := new(Nat)
	case2Mag.And(xAbsMinus1, yNot)
	case2Mag.Increment()

	// Case 3: x positive, y negative
	// result = -((|y|-1) & ~x + 1)
	yAbsMinus1 := new(Nat)
	yAbsMinus1.Set(yAbs)
	yAbsMinus1.Decrement()

	xNot := new(Nat)
	xNot.NotCap(xAbs, int(xAbs.AnnouncedLen()))

	case3Mag := new(Nat)
	case3Mag.And(yAbsMinus1, xNot)
	case3Mag.Increment()

	// Case 4: Both negative
	// result = -((|x|-1) & (|y|-1) + 1)
	case4Mag := new(Nat)
	case4Mag.And(xAbsMinus1, yAbsMinus1)
	case4Mag.Increment()

	// Select the appropriate result using constant-time selection
	resultMag := new(Nat)
	resultMag.SetZero()
	resultMag.CondAssign(bothPos, case1)
	resultMag.CondAssign(xNegYPos, case2Mag)
	resultMag.CondAssign(xPosYNeg, case3Mag)
	resultMag.CondAssign(bothNeg, case4Mag)

	// Set sign - negative unless both positive
	i.SetNat(resultMag)
	i.CondNeg(bothPos.Not())
	if cap >= 0 {
		i.Resize(cap)
	}
}

// Xor sets i = x ^ y and returns i.
// For signed integers, this operates on the two's complement representation.
func (i *Int) Xor(x, y *Int) {
	i.XorCap(x, y, -1)
}

// XorCap sets i = x ^ y with capacity cap and returns i.
// For signed integers, this operates on the two's complement representation.
func (i *Int) XorCap(x, y *Int, cap int) {
	// XOR truth table for two's complement:
	// x >= 0, y >= 0: x ^ y (always positive)
	// x < 0,  y >= 0: ~(~x ^ y) = -((x-1) ^ y + 1)
	// x >= 0, y < 0:  ~(x ^ ~y) = -((x ^ (y-1)) + 1)
	// x < 0,  y < 0:  (~x) ^ (~y) = (x-1) ^ (y-1)

	xNeg := x.IsNegative()
	yNeg := y.IsNegative()

	bothPos := xNeg.Not() & yNeg.Not()
	xNegYPos := xNeg & yNeg.Not()
	xPosYNeg := xNeg.Not() & yNeg
	bothNeg := xNeg & yNeg

	// Get magnitudes
	xMag := x.abs()
	yMag := y.abs()

	// Case 1: Both positive - simple XOR
	case1 := new(Nat)
	case1.XorCap(xMag, yMag, cap)

	// Case 2: x negative, y positive
	// Result = -((x-1) ^ y + 1)
	xMinus1 := new(Nat)
	xMinus1.Set(xMag)
	xMinus1.Decrement()

	case2 := new(Nat)
	case2.XorCap(xMinus1, yMag, cap)
	case2.Increment() // Add 1
	// This will be negated

	// Case 3: x positive, y negative
	// Result = -((x ^ (y-1)) + 1)
	yMinus1 := new(Nat)
	yMinus1.Set(yMag)
	yMinus1.Decrement()

	case3 := new(Nat)
	case3.XorCap(xMag, yMinus1, cap)
	case3.Increment() // Add 1
	// This will be negated

	// Case 4: Both negative
	// Result = (x-1) ^ (y-1)
	case4 := new(Nat)
	case4.XorCap(xMinus1, yMinus1, cap)

	// Select the appropriate result
	resultMag := new(Nat)
	resultMag.Set(case1)
	resultMag.CondAssign(ct.Choice(bothPos), case1)
	resultMag.CondAssign(ct.Choice(xNegYPos), case2)
	resultMag.CondAssign(ct.Choice(xPosYNeg), case3)
	resultMag.CondAssign(ct.Choice(bothNeg), case4)

	// Determine if result should be negative
	// Negative when: xNegYPos OR xPosYNeg
	resultNeg := xNegYPos | xPosYNeg

	// Set the result
	i.SetNat(resultMag)
	i.CondNeg(ct.Choice(resultNeg))
	if cap >= 0 {
		i.Resize(cap)
	}
}

// Not sets i = ^x and returns i.
// For signed integers, this is equivalent to -(x+1) due to two's complement.
func (i *Int) Not(x *Int) {
	i.NotCap(x, -1)
}

// NotCap sets i = ^x with capacity cap and returns i.
// For signed integers, this is equivalent to -(x+1) due to two's complement.
func (i *Int) NotCap(x *Int, cap int) {
	// In two's complement, NOT(x) = -(x+1)
	// This is because ~x = -x - 1 in two's complement

	// Compute x + 1
	one := NewInt(1)
	xPlusOne := new(Int)
	xPlusOne.AddCap(x, one, cap)

	// Negate the result
	i.Neg(xPlusOne)
	if cap >= 0 {
		i.Resize(cap)
	}
}
