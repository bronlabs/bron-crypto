package uint256

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/ct"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/cronokirby/saferith"
	"golang.org/x/crypto/sha3"
	"io"
)

type Zn struct {
	order *saferith.Nat
}

var zn = &Zn{}

var _ algebra.AbstractZn[*Zn, U256] = zn

func NewZn() *Zn {
	return zn
}

func (z *Zn) Name() string {
	return "ZnU256"
}

func (z *Zn) Element() U256 {
	return Zero
}

func (z *Zn) Order() *saferith.Modulus {
	//TODO implement me
	panic("implement me")
}

func (z *Zn) Operators() []algebra.Operator {
	return []algebra.Operator{algebra.Addition, algebra.Multiplication}
}

func (z *Zn) OperateOver(operator algebra.Operator, xs ...U256) (U256, error) {
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

	return U256{}, errs.NewFailed("unsupported operator")
}

func (z *Zn) Random(prng io.Reader) (U256, error) {
	var buffer [32]byte
	_, err := io.ReadFull(prng, buffer[:])
	if err != nil {
		return U256{}, errs.WrapRandomSample(err, "random failed")
	}

	return NewFromBytesLE(buffer[:]), nil
}

func (z *Zn) Hash(x []byte) (U256, error) {
	digest := sha3.Sum256(x)
	return NewFromBytesLE(digest[:]), nil
}

func (z *Zn) Select(choice int, x0, x1 U256) U256 {
	v := uint64(1 - choice)
	r := U256{
		Limb0: ct.Select(v, x0.Limb0, x1.Limb0),
		Limb1: ct.Select(v, x0.Limb1, x1.Limb1),
		Limb2: ct.Select(v, x0.Limb2, x1.Limb2),
		Limb3: ct.Select(v, x0.Limb3, x1.Limb3),
	}
	return r
}

func (z *Zn) Add(x U256, ys ...U256) U256 {
	r := x
	for _, y := range ys {
		r = r.Add(y)
	}
	return r
}

func (z *Zn) AdditiveIdentity() U256 {
	return Zero
}

func (z *Zn) Sub(x U256, ys ...U256) U256 {
	r := x
	for _, y := range ys {
		r = r.Sub(y)
	}
	return r
}

func (z *Zn) Multiply(x U256, ys ...U256) U256 {
	r := x
	for _, y := range ys {
		r = r.Mul(y)
	}
	return r
}

func (z *Zn) MultiplicativeIdentity() U256 {
	return One
}

func (z *Zn) QuadraticResidue(p U256) (U256, error) {
	panic("not implement me")
}

func (z *Zn) Characteristic() *saferith.Nat {
	panic("not implement me")
}

func (z *Zn) Join(x, y U256) U256 {
	return x.Join(y)
}

func (z *Zn) Meet(x, y U256) U256 {
	return x.Meet(y)
}

func (z *Zn) New(v uint64) U256 {
	return U256{
		Limb0: v,
		Limb1: 0,
		Limb2: 0,
		Limb3: 0,
	}
}

func (z *Zn) Zero() U256 {
	return Zero
}

func (z *Zn) One() U256 {
	return One
}

func (z *Zn) Top() U256 {
	return Max
}

func (z *Zn) Bottom() U256 {
	return Zero
}

func (z *Zn) Max(x U256, ys ...U256) U256 {
	r := x
	for _, y := range ys {
		r = r.Max(y)
	}
	return r
}

func (z *Zn) Min(x U256, ys ...U256) U256 {
	r := x
	for _, y := range ys {
		r = r.Min(y)
	}
	return r
}
