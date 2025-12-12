package num

import (
	"io"
	"math/big"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
)

var (
	qOnce     sync.Once
	qInstance *Rationals
)

// Q returns the singleton instance of the Rationals structure.
func Q() *Rationals {
	qOnce.Do(func() {
		qInstance = &Rationals{}
	})
	return qInstance
}

// Rationals represents the field of rational numbers Q.
type Rationals struct{}

// Name returns the name of the structure.
func (q *Rationals) Name() string {
	return "Q"
}

// Characteristic returns the characteristic of the field Q, which is 0.
func (q *Rationals) Characteristic() algebra.Cardinal {
	return cardinal.New(0)
}

// Order returns the order of the field Q, which is infinite.
func (q *Rationals) Order() algebra.Cardinal {
	return cardinal.Infinite()
}

// ElementSize returns -1 to indicate that elements of Q do not have a fixed size.
func (q *Rationals) ElementSize() int {
	return -1
}

// ExtensionDegree returns the extension degree of Q over itself, which is 1.
func (q *Rationals) ExtensionDegree() uint {
	return 1
}

// New creates a new Rat element with the given numerator and denominator.
func (q *Rationals) New(a *Int, b *NatPlus) (*Rat, error) {
	if a == nil || b == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	return &Rat{
		a: a,
		b: b,
	}, nil
}

// FromBytes deserializes a Rat element from the given byte slice.
func (q *Rationals) FromBytes(data []byte) (*Rat, error) {
	var r Rat
	if err := r.UnmarshalCBOR(data); err != nil {
		return nil, errs2.Wrap(err)
	}
	return &r, nil
}

// FromUint64 creates a Rat element from a uint64 value.
func (q *Rationals) FromUint64(n uint64) *Rat {
	return &Rat{
		a: Z().FromUint64(n),
		b: NPlus().One(),
	}
}

// FromInt64 creates a Rat element from an int64 value.
func (q *Rationals) FromInt64(n int64) *Rat {
	return &Rat{
		a: Z().FromInt64(n),
		b: NPlus().One(),
	}
}

// FromNatPlus creates a Rat element from a NatPlus value.
func (q *Rationals) FromNatPlus(n *NatPlus) (*Rat, error) {
	if n == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	return &Rat{
		a: n.Lift(),
		b: NPlus().One(),
	}, nil
}

// FromNat creates a Rat element from a Nat value.
func (q *Rationals) FromNat(n *Nat) (*Rat, error) {
	if n == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	return &Rat{
		a: n.Lift(),
		b: NPlus().One(),
	}, nil
}

// FromInt creates a Rat element from an Int value.
func (q *Rationals) FromInt(n *Int) (*Rat, error) {
	if n == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	return &Rat{
		a: n.Clone(),
		b: NPlus().One(),
	}, nil
}

// FromUint creates a Rat element from a Uint value.
func (q *Rationals) FromUint(n *Uint) (*Rat, error) {
	if n == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	return &Rat{
		a: n.Lift(),
		b: NPlus().One(),
	}, nil
}

// FromBig creates a *Rat element from a *big.Int value.
func (q *Rationals) FromBig(n *big.Int) (*Rat, error) {
	if n == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	a, err := Z().FromBig(n)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return &Rat{
		a: a,
		b: NPlus().One(),
	}, nil
}

// FromBigRat creates a *Rat element from a *big.Rat value.
func (q *Rationals) FromBigRat(n *big.Rat) (*Rat, error) {
	if n == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	a, err := Z().FromBig(n.Num())
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	b, err := NPlus().FromBig(n.Denom())
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return &Rat{
		a: a,
		b: b,
	}, nil
}

// Random samples a random *Rat element in the interval [lowInclusive, highExclusive)
func (q *Rationals) Random(lowInclusive, highExclusive *Rat, prng io.Reader) (*Rat, error) {
	if prng == nil || lowInclusive == nil || highExclusive == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	// Validate interval [lowInclusive, highExclusive)
	if !lowInclusive.IsLessThanOrEqual(highExclusive) {
		return nil, ErrOutOfRange.WithStackFrame().WithMessage("lowInclusive is greater than highExclusive")
	}
	if lowInclusive.Equal(highExclusive) {
		return nil, errs2.New("interval is empty")
	}

	// Sample on the lattice with common denominator D = b1*b2.
	// Any rational n/D with n in [a1*b2, a2*b1) lies in [lowInclusive, highExclusive).
	D := lowInclusive.b.Mul(highExclusive.b)
	lowN := lowInclusive.a.Mul(highExclusive.b.Lift())  // a1*b2
	highN := highExclusive.a.Mul(lowInclusive.b.Lift()) // a2*b1

	n, err := Z().Random(lowN, highN, prng)
	if err != nil {
		return nil, errs2.Wrap(err)
	}

	return (&Rat{a: n, b: D}).Canonical(), nil
}

// RandomInt samples a random integer *Int element in the interval [lowInclusive, highExclusive).
//
// The valid integers are those n satisfying lowInclusive <= n < highExclusive, which is
// equivalent to the half-open integer interval [ceil(lowInclusive), ceil(highExclusive)).
//
// Returns ErrOutOfRange if the interval contains no integers.
func (q *Rationals) RandomInt(lowInclusive, highExclusive *Rat, prng io.Reader) (*Int, error) {
	if prng == nil || lowInclusive == nil || highExclusive == nil {
		return nil, ErrIsNil.WithStackFrame()
	}

	// Validate [lowInclusive, highExclusive)
	if !lowInclusive.IsLessThanOrEqual(highExclusive) {
		return nil, ErrOutOfRange.WithStackFrame().WithMessage("lowInclusive is greater than highExclusive")
	}

	// Integers n with lowInclusive <= n < highExclusive are exactly those in
	// the half-open interval [ceil(lowInclusive), ceil(highExclusive)).
	lowInt, err := lowInclusive.Ceil()
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	highIntExclusive, err := highExclusive.Ceil()
	if err != nil {
		return nil, errs2.Wrap(err)
	}

	// If ceil(low) >= ceil(high), there is no integer n with low <= n < high.
	if !lowInt.Compare(highIntExclusive).IsLessThan() {
		return nil, ErrOutOfRange.WithStackFrame().WithMessage("no integers in the specified interval")
	}

	// Z().Random samples from [lowInt, highIntExclusive), matching the integer
	// points in [lowInclusive, highExclusive).
	result, err := Z().Random(lowInt, highIntExclusive, prng)
	if err != nil {
		// Wrap any error from Z().Random as ErrOutOfRange for consistent error handling.
		// This can happen if highIntExclusive is zero (Z().Random requires non-zero high bound).
		return nil, ErrOutOfRange.WithStackFrame().WithMessage("failed to sample integer in interval: %v", err)
	}
	return result, nil
}

// IsSemiDomain indicates that Q is a semi-domain.
func (q *Rationals) IsSemiDomain() bool {
	return true
}

// OpIdentity returns the additive identity element of Q.
func (q *Rationals) OpIdentity() *Rat {
	return q.One()
}

// Zero returns the zero element of Q.
func (q *Rationals) Zero() *Rat {
	return &Rat{
		a: Z().Zero(),
		b: NPlus().One(),
	}
}

// One returns the multiplicative identity element of Q.
func (q *Rationals) One() *Rat {
	return &Rat{
		a: Z().One(),
		b: NPlus().One(),
	}
}

// Rat represents an element of the field of rational numbers Q.
type Rat struct {
	a *Int
	b *NatPlus
}

// Numerator returns the numerator of the Rat element.
func (r *Rat) Numerator() *Int {
	return r.a
}

// Denominator returns the denominator of the Rat element.
func (r *Rat) Denominator() *NatPlus {
	return r.b
}

// Ceil returns the smallest integer greater than or equal to the Rat element.
func (r *Rat) Ceil() (*Int, error) {
	quot, rem, err := r.a.EuclideanDiv(r.b.Lift())
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	if rem.IsZero() {
		return quot, nil
	}
	return quot.Increment(), nil
}

// Floor returns the largest integer less than or equal to the Rat element.
func (r *Rat) Floor() (*Int, error) {
	quot, _, err := r.a.EuclideanDiv(r.b.Lift())
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return quot, nil
}

// Structure returns the algebraic structure to which the Rat element belongs.
func (r *Rat) Structure() algebra.Structure[*Rat] {
	return Q()
}

// Op performs addition of two Rat elements.
func (r *Rat) Op(rhs *Rat) *Rat {
	return r.Add(rhs)
}

// Add performs addition of two Rat elements.
func (r *Rat) Add(rhs *Rat) *Rat {
	return &Rat{
		a: r.a.Mul(rhs.b.Lift()).Add(rhs.a.Mul(r.b.Lift())),
		b: r.b.Mul(rhs.b),
	}
}

// Double returns the result of adding the Rat element to itself.
func (r *Rat) Double() *Rat {
	return r.Add(r)
}

// TrySub performs subtraction of two Rat elements.
func (r *Rat) TrySub(rhs *Rat) (*Rat, error) {
	return r.Sub(rhs), nil
}

// Sub performs subtraction of two Rat elements.
func (r *Rat) Sub(rhs *Rat) *Rat {
	return &Rat{
		a: r.a.Mul(rhs.b.Lift()).Sub(rhs.a.Mul(r.b.Lift())),
		b: r.b.Mul(rhs.b),
	}
}

// OtherOp performs multiplication of two Rat elements.
func (r *Rat) OtherOp(rhs *Rat) *Rat {
	return r.Mul(rhs)
}

// Mul performs multiplication of two Rat elements.
func (r *Rat) Mul(rhs *Rat) *Rat {
	return &Rat{
		a: r.a.Mul(rhs.a),
		b: r.b.Mul(rhs.b),
	}
}

// Square returns the square of the Rat element.
func (r *Rat) Square() *Rat {
	return r.Mul(r)
}

// EuclideanDiv performs Euclidean division of two Rat elements.
func (r *Rat) EuclideanDiv(rhs *Rat) (quo *Rat, rem *Rat, err error) {
	quo, err = r.TryDiv(rhs)
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}
	return quo, Q().Zero(), nil
}

// EuclideanValuation returns the Euclidean valuation of the Rat element.
func (r *Rat) EuclideanValuation() cardinal.Cardinal {
	if r.IsZero() {
		return cardinal.Zero()
	}
	return cardinal.New(1)
}

// TryDiv performs division of two Rat elements.
func (r *Rat) TryDiv(rhs *Rat) (*Rat, error) {
	if rhs.IsZero() {
		return nil, errs2.New("division by zero")
	}
	numerator := r.a.Mul(rhs.b.Lift())
	// Handle sign: if rhs.a is negative, negate the numerator
	absRhsA := rhs.a
	if rhs.a.IsNegative() {
		numerator = numerator.Neg()
		absRhsA = rhs.a.Neg()
	}
	rhsANP, err := NPlus().FromInt(absRhsA)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return &Rat{
		a: numerator,
		b: r.b.Mul(rhsANP),
	}, nil
}

// TryOpInv returns the additive inverse of the Rat element.
func (r *Rat) TryOpInv() (*Rat, error) {
	return r.TryNeg()
}

// OpInv returns the additive inverse of the Rat element.
func (r *Rat) OpInv() *Rat {
	return r.Neg()
}

// TryNeg returns the additive inverse of the Rat element.
func (r *Rat) TryNeg() (*Rat, error) {
	return r.Neg(), nil
}

// Neg returns the additive inverse of the Rat element.
func (r *Rat) Neg() *Rat {
	return &Rat{
		a: r.a.Neg(),
		b: r.b,
	}
}

// TryInv returns the multiplicative inverse of the Rat element.
func (r *Rat) TryInv() (*Rat, error) {
	if r.IsZero() {
		return nil, errs2.New("inversion of zero")
	}
	// Swap numerator and denominator: a/b becomes b/a
	// Handle sign: if a is negative, result should have negative numerator
	absA := r.a
	sign := false
	if r.a.IsNegative() {
		absA = r.a.Neg()
		sign = true
	}
	bAsNP, err := NPlus().FromInt(absA)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	numerator := r.b.Lift()
	if sign {
		numerator = numerator.Neg()
	}
	return &Rat{
		a: numerator,
		b: bAsNP,
	}, nil
}

// IsOpIdentity checks if the Rat element is the additive identity (zero).
func (r *Rat) IsOpIdentity() bool {
	return r.a.IsZero()
}

// IsZero checks if the Rat element is zero.
func (r *Rat) IsZero() bool {
	return r.a.IsZero()
}

// IsOne checks if the Rat element is one.
func (r *Rat) IsOne() bool {
	return r.a.Equal(r.b.Lift())
}

// Canonical returns the canonical form of the Rat element.
func (r *Rat) Canonical() *Rat {
	if r.IsZero() {
		return &Rat{a: Z().Zero(), b: NPlus().One()}
	}
	if r.Denominator().IsOne() {
		return &Rat{a: r.a.Clone(), b: NPlus().One()}
	}
	gcd := r.a.Abs().GCD(r.b.Nat())
	if gcd.IsOne() { // Already canonical
		return &Rat{a: r.a.Clone(), b: r.b.Clone()}
	}
	// Divide numerator and denominator by gcd
	num, r1, err := r.a.EuclideanDiv(gcd.Lift())
	if err != nil || !r1.IsZero() {
		return &Rat{a: r.a.Clone(), b: r.b.Clone()}
	}
	den, r2, err := r.b.Lift().EuclideanDiv(gcd.Lift())
	if err != nil || !r2.IsZero() {
		return &Rat{a: r.a.Clone(), b: r.b.Clone()}
	}
	den2, err := NPlus().FromInt(den)
	if err != nil {
		panic(errs2.Wrap(err))
	}
	return &Rat{a: num, b: den2}
}

// IsInt checks if the Rat element is an integer.
func (r *Rat) IsInt() bool {
	return r.Canonical().Denominator().IsOne()
}

// IsProbablyPrime checks if the Rat element is probably prime.
func (r *Rat) IsProbablyPrime() bool {
	canonical := r.Canonical()
	return canonical.Denominator().IsOne() && canonical.Numerator().IsProbablyPrime()
}

// Clone creates a deep copy of the Rat element.
func (r *Rat) Clone() *Rat {
	return &Rat{
		a: r.a.Clone(),
		b: r.b.Clone(),
	}
}

// IsLessThanOrEqual checks if the Rat element is less than another Rat element.
func (r *Rat) IsLessThanOrEqual(rhs *Rat) bool {
	left := r.a.Mul(rhs.b.Lift())
	right := rhs.a.Mul(r.b.Lift())
	return left.IsLessThanOrEqual(right)
}

// IsNegative checks if the Rat element is negative.
func (r *Rat) IsNegative() bool {
	return r.a.IsNegative()
}

// IsPositive checks if the Rat element is positive.
func (r *Rat) IsPositive() bool {
	return !r.IsNegative() && !r.IsZero()
}

// Equal checks if the Rat element is equal to another Rat element.
func (r *Rat) Equal(rhs *Rat) bool {
	return r.a.Mul(rhs.b.Lift()).Equal(r.b.Lift().Mul(rhs.a))
}

// Bytes serializes the Rat element to a byte slice.
func (r *Rat) Bytes() []byte {
	out, err := r.MarshalCBOR()
	if err != nil {
		panic(errs2.Wrap(err))
	}
	return out
}

func (r *Rat) Big() *big.Rat {
	num := r.a.Big()
	den := r.b.Big()
	return big.NewRat(0, 1).SetFrac(num, den)
}

// HashCode computes the hash code of the Rat element.
func (r *Rat) HashCode() base.HashCode {
	return r.a.HashCode().Combine(r.b.HashCode())
}

// String returns the string representation of the Rat element.
func (r *Rat) String() string {
	return r.a.String() + "/" + r.b.String()
}
