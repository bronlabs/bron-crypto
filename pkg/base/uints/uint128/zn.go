package uint128

import (
	"io"

	"github.com/cronokirby/saferith"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/ct"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type Zn struct{}

var zn *Zn

var _ algebra.AbstractZn[*Zn, U128] = zn

func NewZn() *Zn {
	return zn
}

func (*Zn) Name() string {
	return "ZnU128"
}

func (*Zn) Element() U128 {
	return Zero
}

func (*Zn) Order() *saferith.Modulus {
	panic("not implemented")
}

func (*Zn) Operators() []algebra.Operator {
	return []algebra.Operator{algebra.Addition, algebra.Multiplication}
}

func (*Zn) OperateOver(operator algebra.Operator, xs ...U128) (U128, error) {
	//nolint:exhaustive // no need to check irrelevant kinds.
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
	default:
		return U128{}, errs.NewFailed("unsupported operator")
	}
}

func (*Zn) Random(prng io.Reader) (U128, error) {
	var buffer [16]byte
	_, err := io.ReadFull(prng, buffer[:])
	if err != nil {
		return U128{}, errs.WrapRandomSample(err, "random failed")
	}

	return NewFromBytesLE(buffer[:]), nil
}

func (*Zn) Hash(x []byte) (U128, error) {
	digest := sha3.Sum256(x)
	return NewFromBytesLE(digest[:16]), nil
}

func (*Zn) Select(choice int, x0, x1 U128) U128 {
	v := uint64(choice)
	r := U128{
		Lo: ct.Select(v, x0.Lo, x1.Lo),
		Hi: ct.Select(v, x0.Hi, x1.Hi),
	}
	return r
}

func (*Zn) Add(x U128, ys ...U128) U128 {
	r := x
	for _, y := range ys {
		r = r.Add(y)
	}
	return r
}

func (*Zn) AdditiveIdentity() U128 {
	return Zero
}

func (*Zn) Sub(x U128, ys ...U128) U128 {
	r := x
	for _, y := range ys {
		r = r.Sub(y)
	}
	return r
}

func (*Zn) Multiply(x U128, ys ...U128) U128 {
	r := x
	for _, y := range ys {
		r = r.Mul(y)
	}
	return r
}

func (*Zn) MultiplicativeIdentity() U128 {
	return One
}

func (*Zn) QuadraticResidue(p U128) (U128, error) {
	panic("not implemented")
}

func (*Zn) Characteristic() *saferith.Nat {
	panic("not implemented")
}

func (*Zn) Join(x, y U128) U128 {
	return x.Join(y)
}

func (*Zn) Meet(x, y U128) U128 {
	return x.Meet(y)
}

func (*Zn) New(v uint64) U128 {
	return U128{
		Lo: v,
		Hi: 0,
	}
}

func (*Zn) Zero() U128 {
	return Zero
}

func (*Zn) One() U128 {
	return One
}

func (*Zn) Top() U128 {
	return Max
}

func (*Zn) Bottom() U128 {
	return Zero
}

func (*Zn) Max(x U128, ys ...U128) U128 {
	r := x
	for _, y := range ys {
		r = r.Max(y)
	}
	return r
}

func (*Zn) Min(x U128, ys ...U128) U128 {
	r := x
	for _, y := range ys {
		r = r.Min(y)
	}
	return r
}
