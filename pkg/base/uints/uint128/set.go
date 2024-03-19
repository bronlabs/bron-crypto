package uint128

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/uints"
	"io"

	"github.com/cronokirby/saferith"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/ct"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type Set struct{}

var set *Set

var _ uints.Set[*Set, U128] = set

func NewSet() *Set {
	return set
}

func (*Set) Name() string {
	return "ZnU128"
}

func (*Set) Element() U128 {
	return Zero
}

func (*Set) Order() *saferith.Modulus {
	panic("not implemented")
}

func (*Set) Operators() []algebra.Operator {
	return []algebra.Operator{algebra.Addition, algebra.Multiplication}
}

func (*Set) OperateOver(operator algebra.Operator, xs ...U128) (U128, error) {
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

func (*Set) Random(prng io.Reader) (U128, error) {
	var buffer [16]byte
	_, err := io.ReadFull(prng, buffer[:])
	if err != nil {
		return U128{}, errs.WrapRandomSample(err, "random failed")
	}

	return NewFromBytesLE(buffer[:]), nil
}

func (*Set) Hash(x []byte) (U128, error) {
	digest := sha3.Sum256(x)
	return NewFromBytesLE(digest[:16]), nil
}

func (*Set) Select(choice int, x0, x1 U128) U128 {
	v := uint64(choice)
	r := U128{
		Lo: ct.Select(v, x0.Lo, x1.Lo),
		Hi: ct.Select(v, x0.Hi, x1.Hi),
	}
	return r
}

func (*Set) Add(x U128, ys ...U128) U128 {
	r := x
	for _, y := range ys {
		r = r.Add(y)
	}
	return r
}

func (*Set) AdditiveIdentity() U128 {
	return Zero
}

func (*Set) Sub(x U128, ys ...U128) U128 {
	r := x
	for _, y := range ys {
		r = r.Sub(y)
	}
	return r
}

func (*Set) Multiply(x U128, ys ...U128) U128 {
	r := x
	for _, y := range ys {
		r = r.Mul(y)
	}
	return r
}

func (*Set) MultiplicativeIdentity() U128 {
	return One
}

func (*Set) QuadraticResidue(p U128) (U128, error) {
	panic("not implemented")
}

func (*Set) Characteristic() *saferith.Nat {
	panic("not implemented")
}

func (*Set) Join(x, y U128) U128 {
	return x.Join(y)
}

func (*Set) Meet(x, y U128) U128 {
	return x.Meet(y)
}

func (*Set) New(v uint64) U128 {
	return U128{
		Lo: v,
		Hi: 0,
	}
}

func (*Set) Zero() U128 {
	return Zero
}

func (*Set) One() U128 {
	return One
}

func (*Set) Top() U128 {
	return Max
}

func (*Set) Bottom() U128 {
	return Zero
}

func (*Set) Max(x U128, ys ...U128) U128 {
	r := x
	for _, y := range ys {
		r = r.Max(y)
	}
	return r
}

func (*Set) Min(x U128, ys ...U128) U128 {
	r := x
	for _, y := range ys {
		r = r.Min(y)
	}
	return r
}
