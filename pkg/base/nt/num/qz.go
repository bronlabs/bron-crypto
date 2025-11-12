package num

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

// var (
// 	_ algebra.Ring[*Fraction]        = (*TotalQuotientRing)(nil)
// 	_ algebra.RingElement[*Fraction] = (*Fraction)(nil)
// )

// func Q(r *ZMod) (*TotalQuotientRing, error) {
// 	if r == nil {
// 		return nil, errs.NewFailed("ZMod is nil")
// 	}
// 	return &TotalQuotientRing{
// 		zMod: *r,
// 	}, nil
// }

type TotalQuotientRing struct {
	zMod ZMod
}

func (tf *TotalQuotientRing) Name() string {
	return fmt.Sprintf("Q[%s]", tf.zMod.Name())
}

func (tf *TotalQuotientRing) Characteristic() algebra.Cardinal {
	panic("not implemented")
}

func (tf *TotalQuotientRing) Order() algebra.Cardinal {
	panic("not implemented")
}

func (tf *TotalQuotientRing) ElementSize() int {
	return max(tf.zMod.ElementSize()*2, -1)
}

func (tf *TotalQuotientRing) ExtensionDegree() uint {
	return 1
}

func (tf *TotalQuotientRing) New(a, b *Uint) (*Fraction, error) {
	if a == nil || b == nil {
		return nil, errs.NewFailed("cannot create Fraction with nil numerator or denominator")
	}
	return &Fraction{
		a: a,
		b: b,
	}, nil
}

// func (tf *TotalQuotientRing) FromBytes(data []byte) (*Fraction, error) {
// 	f := &Fraction{}
// 	if err := f.UnmarshalCBOR(data); err != nil {
// 		return nil, errs.WrapFailed(err, "could not convert from bytes to Fraction")
// 	}
// 	return f, nil
// }

func (tf *TotalQuotientRing) FromUint64(n uint64) (*Fraction, error) {
	a, err := tf.zMod.FromUint64(n)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert from uint64")
	}
	return &Fraction{
		a: a,
		b: tf.zMod.One(),
	}, nil
}

func (tf *TotalQuotientRing) FromInt64(n int64) (*Fraction, error) {
	a, err := tf.zMod.FromInt64(n)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert from int64")
	}
	return &Fraction{
		a: a,
		b: tf.zMod.One(),
	}, nil
}

func (tf *TotalQuotientRing) FromNatPlus(n *NatPlus) (*Fraction, error) {
	a, err := tf.zMod.FromNatPlus(n)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert from NatPlus")
	}
	return &Fraction{
		a: a,
		b: tf.zMod.One(),
	}, nil
}

func (tf *TotalQuotientRing) FromNat(n *Nat) (*Fraction, error) {
	a, err := tf.zMod.FromNat(n)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert from Nat")
	}
	return &Fraction{
		a: a,
		b: tf.zMod.One(),
	}, nil
}

func (tf *TotalQuotientRing) FromInt(n *Int) (*Fraction, error) {
	a, err := tf.zMod.FromInt(n)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert from Int")
	}
	return &Fraction{
		a: a,
		b: tf.zMod.One(),
	}, nil
}

func (tf *TotalQuotientRing) FromUint(n *Uint) (*Fraction, error) {
	if !tf.Modulus().Equal(n.Modulus()) {
		return nil, errs.NewFailed("cannot convert Uint with different modulus to Fraction")
	}
	return &Fraction{
		a: n.Clone(),
		b: tf.zMod.One(),
	}, nil
}

// func (tf *TotalQuotientRing) Random(lowInclusive, highExclusive *Fraction, prng io.Reader) (*Fraction, error) {
// 	if lowInclusive == nil || highExclusive == nil {
// 		return nil, errs.NewIsNil("bound")
// 	}
// 	if !lowInclusive.EqualModulus(highExclusive) {
// 		return nil, errs.NewFailed("bounds must have the same modulus")
// 	}
// 	if highExclusive.IsLessThanOrEqual(lowInclusive) && !highExclusive.Equal(lowInclusive) {
// 		return nil, errs.NewFailed("highExclusive must be greater than lowInclusive")
// 	}

// }

func (tf *TotalQuotientRing) RandomUint(lowInclusive, highExclusive *Fraction, prng io.Reader) (*Uint, error) {
	panic("not implemented")
}

func (tf *TotalQuotientRing) IsSemiDomain() bool {
	return tf.zMod.IsSemiDomain()
}

func (tf *TotalQuotientRing) OpIdentity() *Fraction {
	return tf.One()
}

func (tf *TotalQuotientRing) One() *Fraction {
	return &Fraction{
		a: tf.zMod.One(),
		b: tf.zMod.One(),
	}
}

func (tf *TotalQuotientRing) Zero() *Fraction {
	return &Fraction{
		a: tf.zMod.Zero(),
		b: tf.zMod.One(),
	}
}

func (tf *TotalQuotientRing) AmbientStructure() algebra.Structure[*Uint] {
	return &tf.zMod
}

func (tf *TotalQuotientRing) Modulus() *NatPlus {
	return tf.zMod.Modulus()
}

type Fraction struct {
	a *Uint
	b *Uint
}

func (f *Fraction) Numerator() *Uint {
	return f.a
}

func (f *Fraction) Denominator() *Uint {
	return f.b
}

func (f *Fraction) Modulus() *NatPlus {
	return f.a.Group().Modulus()
}

// func (f *Fraction) Structure() algebra.Structure[*Fraction] {
// 	return &TotalQuotientRing{
// 		zMod: *f.a.Group(),
// 	}
// }

func (r *Fraction) Ceil() (*Uint, error) {
	quot, rem, err := r.a.EuclideanDiv(r.b)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't compute division for ceil")
	}
	if rem.IsZero() || quot.IsNegative() {
		return quot, nil
	}
	return quot.Increment(), nil
}

func (f *Fraction) Op(rhs *Fraction) *Fraction {
	return f.Add(rhs)
}

func (f *Fraction) Add(rhs *Fraction) *Fraction {
	return &Fraction{
		a: f.a.Mul(rhs.b).Add(rhs.a.Mul(f.b)),
		b: f.b.Mul(rhs.b),
	}
}

func (f *Fraction) Double() *Fraction {
	return f.Add(f)
}

func (f *Fraction) TrySub(rhs *Fraction) (*Fraction, error) {
	return f.Sub(rhs), nil
}

func (f *Fraction) Sub(rhs *Fraction) *Fraction {
	return &Fraction{
		a: f.a.Mul(rhs.b).Sub(rhs.a.Mul(f.b)),
		b: f.b.Mul(rhs.b),
	}
}

func (f *Fraction) OtherOp(rhs *Fraction) *Fraction {
	return f.Mul(rhs)
}

func (f *Fraction) Mul(rhs *Fraction) *Fraction {
	return &Fraction{
		a: f.a.Mul(rhs.a),
		b: f.b.Mul(rhs.b),
	}
}

func (f *Fraction) Square() *Fraction {
	return f.Mul(f)
}

func (f *Fraction) TryDiv(rhs *Fraction) (*Fraction, error) {
	return &Fraction{
		a: f.a.Mul(rhs.b),
		b: f.b.Mul(rhs.a),
	}, nil
}

func (f *Fraction) TryOpInv() (*Fraction, error) {
	return f.TryNeg()
}

func (f *Fraction) OpInv() *Fraction {
	return f.Neg()
}

func (f *Fraction) TryNeg() (*Fraction, error) {
	return f.Neg(), nil
}

func (f *Fraction) Neg() *Fraction {
	return &Fraction{
		a: f.a.Neg(),
		b: f.b,
	}
}

func (f *Fraction) TryInv() (*Fraction, error) {
	return &Fraction{
		a: f.b,
		b: f.a,
	}, nil
}

func (f *Fraction) Inv() *Fraction {
	out, err := f.TryInv()
	if err != nil {
		panic(err)
	}
	return out
}

func (f *Fraction) IsOpIdentity() bool {
	return f.a.IsZero()
}

func (f *Fraction) IsZero() bool {
	return f.a.IsZero()
}

func (f *Fraction) IsOne() bool {
	return f.a.Equal(f.b)
}

func (f *Fraction) Clone() *Fraction {
	return &Fraction{
		a: f.a.Clone(),
		b: f.b.Clone(),
	}
}

func (f *Fraction) Equal(rhs *Fraction) bool {
	return f.a.Mul(rhs.b).Equal(f.b.Mul(rhs.a))
}

func (f *Fraction) IsLessThanOrEqual(rhs *Fraction) bool {
	return f.a.Mul(rhs.b).IsLessThanOrEqual(f.b.Mul(rhs.a))
}

func (f *Fraction) EqualModulus(other *Fraction) bool {
	if !f.a.Modulus().Equal(f.b.Modulus()) {
		panic("fraction has inconsistent modulus between numerator and denominator")
	}
	return (f.a.Modulus().Equal(other.a.Modulus()) &&
		f.b.Modulus().Equal(other.b.Modulus()))
}

// func (f *Fraction) Bytes() []byte {
// 	out, err := f.MarshalCBOR()
// 	if err != nil {
// 		panic(err)
// 	}
// 	return out
// }

func (f *Fraction) String() string {
	return fmt.Sprintf("%s/%s", f.a.String(), f.b.String())
}

func (f *Fraction) HashCode() base.HashCode {
	return f.a.HashCode().Combine(f.b.HashCode())
}

func (r *Fraction) Canonical() *Fraction {
	g := r.a.Group()

	// Normalize 0 to 0/1
	if r.IsZero() {
		return &Fraction{a: g.Zero(), b: g.One()}
	}
	// gcd(a, b) via Euclidean algorithm
	a := r.a.Clone()
	b := r.b.Clone()
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
		return &Fraction{a: r.a.Clone(), b: r.b.Clone()}
	}

	// Divide numerator and denominator by gcd
	num, r1, err := r.a.EuclideanDiv(gcd)
	if err != nil || !r1.IsZero() {
		return &Fraction{a: r.a.Clone(), b: r.b.Clone()}
	}
	den, r2, err := r.b.EuclideanDiv(gcd)
	if err != nil || !r2.IsZero() {
		return &Fraction{a: r.a.Clone(), b: r.b.Clone()}
	}

	return &Fraction{a: num, b: den}
}

func (r *Fraction) IsUint() bool {
	return r.Canonical().Denominator().IsOne()
}
