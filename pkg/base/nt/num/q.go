package num

import (
	"io"
	"math/big"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/cronokirby/saferith"
)

var _ algebra.Field[*Rat] = (*Rationals)(nil)

var (
	qOnce     sync.Once
	qInstance *Rationals
)

func Q() *Rationals {
	qOnce.Do(func() {
		qInstance = &Rationals{}
	})
	return qInstance
}

type Rationals struct{}

func (q *Rationals) Name() string {
	return "Q"
}

func (q *Rationals) Characteristic() algebra.Cardinal {
	return cardinal.New(0)
}

func (q *Rationals) Order() algebra.Cardinal {
	return cardinal.Infinite()
}

func (q *Rationals) ElementSize() int {
	return -1
}

func (q *Rationals) ExtensionDegree() uint {
	return 1
}

func (q *Rationals) New(a *Int, b *NatPlus) (*Rat, error) {
	if a == nil || b == nil {
		return nil, errs.NewIsNil("cannot create Rat with nil numerator or denominator")
	}
	return &Rat{
		a: a,
		b: b,
	}, nil
}

func (q *Rationals) FromBytes(data []byte) (*Rat, error) {
	var r Rat
	if err := r.UnmarshalCBOR(data); err != nil {
		return nil, errs.WrapSerialisation(err, "couldn't unmarshal Rat from bytes")
	}
	return &r, nil
}

func (q *Rationals) FromUint64(n uint64) *Rat {
	return &Rat{
		a: Z().FromUint64(n),
		b: NPlus().One(),
	}
}

func (q *Rationals) FromInt64(n int64) *Rat {
	return &Rat{
		a: Z().FromInt64(n),
		b: NPlus().One(),
	}
}

func (q *Rationals) FromNatPlus(n *NatPlus) (*Rat, error) {
	if n == nil {
		return nil, errs.NewIsNil("cannot convert nil NatPlus to Rat")
	}
	return &Rat{
		a: n.Lift(),
		b: n.Clone(),
	}, nil
}

func (q *Rationals) FromNat(n *Nat) (*Rat, error) {
	if n == nil {
		return nil, errs.NewIsNil("cannot convert nil Nat to Rat")
	}
	return &Rat{
		a: n.Lift(),
		b: NPlus().One(),
	}, nil
}

func (q *Rationals) FromInt(n *Int) (*Rat, error) {
	if n == nil {
		return nil, errs.NewIsNil("cannot convert nil Int to Rat")
	}
	return &Rat{
		a: n.Clone(),
		b: NPlus().One(),
	}, nil
}

func (q *Rationals) FromUint(n *Uint) (*Rat, error) {
	if n == nil {
		return nil, errs.NewIsNil("cannot convert nil Uint to Rat")
	}
	return &Rat{
		a: n.Lift(),
		b: NPlus().One(),
	}, nil
}

func (q *Rationals) FromBig(n *big.Int) (*Rat, error) {
	if n == nil {
		return nil, errs.NewIsNil("cannot convert nil big.Int to Rat")
	}
	a, err := Z().FromBig(n)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't convert big.Int to Int")
	}
	return &Rat{
		a: a,
		b: NPlus().One(),
	}, nil
}

func (q *Rationals) FromBigRat(n *big.Rat) (*Rat, error) {
	if n == nil {
		return nil, errs.NewIsNil("cannot convert nil big.Rat to Rat")
	}
	a, err := Z().FromBig(n.Num())
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't convert big.Rat numerator to Int")
	}
	b, err := NPlus().FromBig(n.Denom())
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't convert big.Rat denominator to NatPlus")
	}
	return &Rat{
		a: a,
		b: b,
	}, nil
}

func (q *Rationals) Random(lowInclusive, highExclusive *Rat, prng io.Reader) (*Rat, error) {
	if prng == nil || lowInclusive == nil || highExclusive == nil {
		return nil, errs.NewIsNil("prng is nil or lowInclusive is nil or highExclusive is nil")
	}
	// Validate interval [lowInclusive, highExclusive)
	if !lowInclusive.IsLessThanOrEqual(highExclusive) {
		return nil, errs.NewValue("lowInclusive is greater than highExclusive")
	}
	if lowInclusive.Equal(highExclusive) {
		return nil, errs.NewValue("interval is empty")
	}

	// Sample on the lattice with common denominator D = b1*b2.
	// Any rational n/D with n in [a1*b2, a2*b1) lies in [lowInclusive, highExclusive).
	D := lowInclusive.b.Mul(highExclusive.b)
	lowN := lowInclusive.a.Mul(highExclusive.b.Lift())  // a1*b2
	highN := highExclusive.a.Mul(lowInclusive.b.Lift()) // a2*b1

	n, err := Z().Random(lowN, highN, prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "failed to sample random numerator for Rat")
	}

	return (&Rat{a: n, b: D}).Canonical(), nil
}

func (q *Rationals) RandomInt(lowInclusive, highExclusive *Rat, prng io.Reader) (*Int, error) {
	if prng == nil || lowInclusive == nil || highExclusive == nil {
		return nil, errs.NewIsNil("prng is nil or lowInclusive is nil or highExclusive is nil")
	}

	// Validate [lowInclusive, highExclusive)
	if !lowInclusive.IsLessThanOrEqual(highExclusive) {
		return nil, errs.NewValue("lowInclusive is greater than highExclusive")
	}

	// ceil(a/b) with b > 0
	lowInt, err := lowInclusive.Ceil()
	if err != nil {
		return nil, err
	}
	highInt, err := highExclusive.Floor()
	if err != nil {
		return nil, err
	}

	// No integers if ceil(low) >= ceil(high)
	if lowInt.Compare(highInt) >= 0 {
		return nil, errs.NewValue("interval contains no integers")
	}

	return Z().Random(lowInt, highInt, prng)
}

func (q *Rationals) IsSemiDomain() bool {
	return true
}

func (q *Rationals) OpIdentity() *Rat {
	return q.One()
}

func (q *Rationals) Zero() *Rat {
	return &Rat{
		a: Z().Zero(),
		b: NPlus().One(),
	}
}

func (q *Rationals) One() *Rat {
	return &Rat{
		a: Z().One(),
		b: NPlus().One(),
	}
}

type Rat struct {
	a *Int
	b *NatPlus
}

func (r *Rat) Numerator() *Int {
	return r.a
}

func (r *Rat) Denominator() *NatPlus {
	return r.b
}

func (r *Rat) Ceil() (*Int, error) {
	quot, rem, err := r.a.EuclideanDiv(r.b.Lift())
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't compute division for ceil")
	}
	if rem.IsZero() || r.a.IsNegative() {
		return quot, nil
	}
	return quot.Increment(), nil
}

func (r *Rat) Floor() (*Int, error) {
	quot, rem, err := r.a.EuclideanDiv(r.b.Lift())
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't compute division for floor")
	}
	if rem.IsZero() || r.a.IsPositive() {
		return quot, nil
	}
	return quot.Decrement(), nil
}

func (r *Rat) Structure() algebra.Structure[*Rat] {
	return Q()
}

func (r *Rat) Op(rhs *Rat) *Rat {
	return r.Add(rhs)
}

func (r *Rat) Add(rhs *Rat) *Rat {
	return &Rat{
		a: r.a.Mul(rhs.b.Lift()).Add(rhs.a.Mul(r.b.Lift())),
		b: r.b.Mul(rhs.b),
	}
}

func (r *Rat) Double() *Rat {
	return r.Add(r)
}

func (r *Rat) TrySub(rhs *Rat) (*Rat, error) {
	return r.Sub(rhs), nil
}

func (r *Rat) Sub(rhs *Rat) *Rat {
	return &Rat{
		a: r.a.Mul(rhs.b.Lift()).Sub(rhs.a.Mul(r.b.Lift())),
		b: r.b.Mul(rhs.b),
	}
}

func (r *Rat) OtherOp(rhs *Rat) *Rat {
	return r.Mul(rhs)
}

func (r *Rat) Mul(rhs *Rat) *Rat {
	return &Rat{
		a: r.a.Mul(rhs.a),
		b: r.b.Mul(rhs.b),
	}
}

func (r *Rat) Square() *Rat {
	return r.Mul(r)
}

func (r *Rat) EuclideanDiv(rhs *Rat) (quo *Rat, rem *Rat, err error) {
	quo, err = r.TryDiv(rhs)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "division by zero")
	}
	return quo, Q().Zero(), nil
}

func (r *Rat) EuclideanValuation() cardinal.Cardinal {
	n := r.Canonical().a.Abs()
	return cardinal.NewFromSaferith((*saferith.Nat)(n.Value()))
}

func (r *Rat) TryDiv(rhs *Rat) (*Rat, error) {
	if rhs.IsZero() {
		return nil, errs.NewValue("division by zero")
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
		return nil, errs.WrapFailed(err, "couldn't convert abs(rhs.a) to NatPlus")
	}
	return &Rat{
		a: numerator,
		b: r.b.Mul(rhsANP),
	}, nil
}

func (r *Rat) TryOpInv() (*Rat, error) {
	return r.TryNeg()
}

func (r *Rat) OpInv() *Rat {
	return r.Neg()
}

func (r *Rat) TryNeg() (*Rat, error) {
	return r.Neg(), nil
}

func (r *Rat) Neg() *Rat {
	return &Rat{
		a: r.a.Neg(),
		b: r.b,
	}
}

func (r *Rat) TryInv() (*Rat, error) {
	if r.IsZero() {
		return nil, errs.NewValue("inversion of zero")
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
		return nil, errs.WrapFailed(err, "couldn't convert abs(a) to NatPlus for inversion")
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

func (r *Rat) Inv() *Rat {
	out, err := r.TryInv()
	if err != nil {
		panic(err)
	}
	return out
}

func (r *Rat) IsOpIdentity() bool {
	return r.a.IsZero()
}

func (r *Rat) IsZero() bool {
	return r.a.IsZero()
}

func (r *Rat) IsOne() bool {
	return r.a.Equal(r.b.Lift())
}

func (r *Rat) Canonical() *Rat {
	// Normalize 0 to 0/1
	if r.IsZero() {
		return &Rat{a: Z().Zero(), b: NPlus().One()}
	}
	// gcd(a, b) via Euclidean algorithm
	a := r.a.Lift()
	b := r.b.Lift()
	for !b.IsZero() {
		_, rem, err := a.EuclideanDiv(b)
		if err != nil {
			panic(errs.WrapFailed(err, "could not compute gcd for canonical fraction"))
		}
		a, b = b, rem
	}
	gcd := a
	// Already reduced?
	if gcd.IsOne() {
		return &Rat{a: r.a.Clone(), b: r.b.Clone()}
	}
	// Divide numerator and denominator by gcd
	num, r1, err := r.a.EuclideanDiv(gcd)
	if err != nil || !r1.IsZero() {
		return &Rat{a: r.a.Clone(), b: r.b.Clone()}
	}
	den, r2, err := r.b.Lift().EuclideanDiv(gcd)
	if err != nil || !r2.IsZero() {
		return &Rat{a: r.a.Clone(), b: r.b.Clone()}
	}
	den2, _ := NPlus().FromInt(den)
	return &Rat{a: num, b: den2}
}

func (r *Rat) IsInt() bool {
	return r.Canonical().Denominator().IsOne()
}

func (r *Rat) IsProbablyPrime() bool {
	canonical := r.Canonical()
	return canonical.Denominator().IsOne() && canonical.Numerator().IsProbablyPrime()
}

func (r *Rat) Clone() *Rat {
	return &Rat{
		a: r.a.Clone(),
		b: r.b.Clone(),
	}
}

func (r *Rat) IsLessThanOrEqual(rhs *Rat) bool {
	left := r.a.Mul(rhs.b.Lift())
	right := rhs.a.Mul(r.b.Lift())
	return left.IsLessThanOrEqual(right)
}

func (r *Rat) IsNegative() bool {
	return r.a.IsNegative()
}

func (r *Rat) IsPositive() bool {
	return !r.IsNegative() && !r.IsZero()
}

func (r *Rat) Equal(rhs *Rat) bool {
	return r.a.Mul(rhs.b.Lift()).Equal(r.b.Lift().Mul(rhs.a))
}

func (r *Rat) Bytes() []byte {
	out, err := r.MarshalCBOR()
	if err != nil {
		panic(errs.WrapSerialisation(err, "couldn't marshal cbor"))
	}
	return out
}

func (r *Rat) HashCode() base.HashCode {
	return r.a.HashCode().Combine(r.b.HashCode())
}

func (r *Rat) String() string {
	return r.a.String() + "/" + r.b.String()
}
