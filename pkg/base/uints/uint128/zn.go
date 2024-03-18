package uint128

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/ct"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/cronokirby/saferith"
	"golang.org/x/crypto/sha3"
	"io"
)

type Zn struct{}

var zn *Zn

var _ algebra.AbstractZn[*Zn, U128] = zn

func NewZn() *Zn {
	return zn
}

func (z *Zn) Name() string {
	return "ZnU128"
}

func (z *Zn) Element() U128 {
	return Zero
}

func (z *Zn) Order() *saferith.Modulus {
	panic("not implemented")
}

func (z *Zn) Operators() []algebra.Operator {
	return []algebra.Operator{algebra.Addition, algebra.Multiplication}
}

func (z *Zn) OperateOver(operator algebra.Operator, xs ...U128) (U128, error) {
	switch operator {
	case algebra.Addition:
		r := Zero
		for _, x := range xs {
			r = r.Add(x)
		}
		return r, nil
	case algebra.Multiplication:
		r := One
		for _, x := range xs {
			r = r.Mul(x)
		}
		return r, nil
	}

	return U128{}, errs.NewFailed("unsupported operator")
}

func (z *Zn) Random(prng io.Reader) (U128, error) {
	var buffer [16]byte
	_, err := io.ReadFull(prng, buffer[:])
	if err != nil {
		return U128{}, errs.WrapRandomSample(err, "random failed")
	}

	return NewFromBytesLE(buffer[:]), nil
}

func (z *Zn) Hash(x []byte) (U128, error) {
	digest := sha3.Sum256(x)
	return NewFromBytesLE(digest[:16]), nil
}

func (z *Zn) Select(choice int, x0, x1 U128) U128 {
	v := uint64(1 - choice)
	r := U128{
		Lo: ct.Select(v, x0.Lo, x1.Lo),
		Hi: ct.Select(v, x0.Hi, x1.Hi),
	}
	return r
}

func (z *Zn) Add(x U128, ys ...U128) U128 {
	r := x
	for _, y := range ys {
		r = r.Add(y)
	}
	return r
}

func (z *Zn) AdditiveIdentity() U128 {
	return Zero
}

func (z *Zn) Sub(x U128, ys ...U128) U128 {
	r := x
	for _, y := range ys {
		r = r.Sub(y)
	}
	return r
}

func (z *Zn) Multiply(x U128, ys ...U128) U128 {
	r := x
	for _, y := range ys {
		r = r.Mul(y)
	}
	return r
}

func (z *Zn) MultiplicativeIdentity() U128 {
	return One
}

func (z *Zn) QuadraticResidue(p U128) (U128, error) {
	panic("not implemented")
}

func (z *Zn) Characteristic() *saferith.Nat {
	panic("not implemented")
}

func (z *Zn) Join(x, y U128) U128 {
	return x.Join(y)
}

func (z *Zn) Meet(x, y U128) U128 {
	return x.Meet(y)
}

func (z *Zn) New(v uint64) U128 {
	return U128{
		Lo: v,
		Hi: 0,
	}
}

func (z *Zn) Zero() U128 {
	return Zero
}

func (z *Zn) One() U128 {
	return One
}

func (z *Zn) Top() U128 {
	return Max
}

func (z *Zn) Bottom() U128 {
	return Zero
}

func (z *Zn) Max(x U128, ys ...U128) U128 {
	r := x
	for _, y := range ys {
		r = r.Max(y)
	}
	return r
}

func (z *Zn) Min(x U128, ys ...U128) U128 {
	r := x
	for _, y := range ys {
		r = r.Min(y)
	}
	return r
}
