package bigint

import (
	"math/big"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
)

var _ integer.Arithmetic[*BigInt] = (*BigArithmetic)(nil)

type BigArithmetic struct {
	bottom  *BigInt
	modulus *BigInt
	size    int
}

func NewSignedArithmetic() *BigArithmetic {
	return &BigArithmetic{}
}

func NewUnsignedArithmetic() *BigArithmetic {
	return &BigArithmetic{
		bottom: Zero,
	}
}

func NewModularArithmetic(modulus *BigInt) *BigArithmetic {
	if modulus == nil {
		panic(errs.NewIsNil("modulus"))
	}
	return &BigArithmetic{
		bottom:  nil,
		modulus: modulus,
		size:    int(modulus.TrueLen()),
	}
}

func NewNPlusArithmetic() *BigArithmetic {
	return &BigArithmetic{
		bottom: One,
	}
}

func (*BigArithmetic) Name() string {
	return Name
}

func (a *BigArithmetic) Clone(x *BigInt) *BigInt {
	return x.Clone()
}

func (a *BigArithmetic) WithoutBottom() integer.Arithmetic[*BigInt] {
	out := NewSignedArithmetic()
	out.size = a.size
	return out
}

func (a *BigArithmetic) WithBottomAtZero() integer.Arithmetic[*BigInt] {
	out := NewSignedArithmetic()
	out.modulus = a.modulus
	out.size = a.size
	return out
}

func (a *BigArithmetic) WithBottomAtOne() integer.Arithmetic[*BigInt] {
	out := NewNPlusArithmetic()
	out.size = a.size
	return nil
}

func (a *BigArithmetic) WithBottomAtZeroAndModulus(m *BigInt) integer.Arithmetic[*BigInt] {
	return NewModularArithmetic(m)
}

func (a *BigArithmetic) WithSize(size int) integer.Arithmetic[*BigInt] {
	if size < 0 {
		size = -1
	}
	return &BigArithmetic{
		bottom:  a.bottom,
		modulus: a.modulus,
		size:    size,
	}
}

func (a *BigArithmetic) Equal(x, y *BigInt) bool {
	return a.Cmp(x, y) == algebra.Equal
}

func (a *BigArithmetic) Cmp(x, y *BigInt) algebra.Ordering {
	return algebra.Ordering(x.Int.Cmp(y.Int))
}

func (a *BigArithmetic) Zero() *BigInt {
	return Zero
}

func (a *BigArithmetic) One() *BigInt {
	return One
}

func (a *BigArithmetic) Two() *BigInt {
	return Two
}

func (a *BigArithmetic) IsEven(x *BigInt) bool {
	out, _ := a.WithoutBottom().Mod(x, a.Two())
	return a.Equal(out, a.One())
}

func (a *BigArithmetic) IsOdd(x *BigInt) bool {
	return !a.IsEven(x)
}

func (a *BigArithmetic) Abs(x *BigInt) *BigInt {
	return B(new(big.Int).Abs(x.Int))
}

func (a *BigArithmetic) Next(x *BigInt) (*BigInt, error) {
	suc, _ := a.WithoutBottom().Add(x, a.One())
	if a.modulus != nil {
		return a.Mod(suc, a.modulus)
	}
	return suc, nil
}

func (a *BigArithmetic) Neg(x *BigInt) (*BigInt, error) {
	if a.bottom != nil && !a.Equal(x, a.Zero()) {
		return nil, errs.NewValue("can't negate nonzero element out of integers")
	}
	return B(new(big.Int).Neg(x.Int)), nil
}

func (a *BigArithmetic) Inverse(x *BigInt) (*BigInt, error) {
	if a.bottom != nil && a.Cmp(x, a.bottom) == algebra.LessThan {
		return nil, errs.NewValue("x < bottom")
	}
	if a.Cmp(x, a.Zero()) == algebra.Equal {
		return nil, errs.NewValue("x == 0")
	}
	if a.modulus != nil {
		return B(new(big.Int).ModInverse(x.Int, a.modulus.Int)), nil
	}
	return B(new(big.Int).Div(One.Int, x.Int)), nil
}

func (a *BigArithmetic) Add(x, y *BigInt) (*BigInt, error) {
	xy := B(new(big.Int).Add(x.Int, y.Int))
	if a.bottom != nil {
		if a.Cmp(x, a.bottom) == algebra.LessThan || a.Cmp(y, a.bottom) == algebra.LessThan {
			return nil, errs.NewValue("x < bottom || y < bottom")
		}
	}
	if a.modulus != nil {
		return a.Mod(xy, a.modulus)
	}
	return xy, nil
}
func (a *BigArithmetic) Sub(x, y *BigInt) (*BigInt, error) {
	xy := B(new(big.Int).Sub(x.Int, y.Int))
	if a.bottom != nil {
		if a.Cmp(x, a.bottom) == algebra.LessThan || a.Cmp(y, a.bottom) == algebra.LessThan || a.Cmp(xy, a.bottom) == algebra.LessThan {
			return nil, errs.NewValue("x < bottom || y < bottom || x + y < bottom")
		}
	}
	if a.modulus != nil {
		return a.Mod(xy, a.modulus)
	}
	return xy, nil
}
func (a *BigArithmetic) Mul(x, y *BigInt) (*BigInt, error) {
	xy := B(new(big.Int).Mul(x.Int, y.Int))
	if a.bottom != nil {
		if a.Cmp(x, a.bottom) == algebra.LessThan || a.Cmp(y, a.bottom) == algebra.LessThan {
			return nil, errs.NewValue("x < bottom || y < bottom")
		}
	}
	if a.modulus != nil {
		return a.Mod(xy, a.modulus)
	}
	return xy, nil
}

func (a *BigArithmetic) Exp(x, y *BigInt) (*BigInt, error) {
	if a.bottom != nil {
		if a.Cmp(x, a.bottom) == algebra.LessThan || a.Cmp(y, a.bottom) == algebra.LessThan {
			return nil, errs.NewValue("x < bottom || y < bottom")
		}
	}
	// should work for both cases of modulus being int or with some value
	return B(new(big.Int).Exp(x.Int, y.Int, a.modulus.Int)), nil
}
func (a *BigArithmetic) Mod(x, m *BigInt) (*BigInt, error) {
	if a.bottom != nil {
		if a.Cmp(x, a.bottom) == algebra.LessThan || a.Cmp(m, a.bottom) == algebra.LessThan {
			return nil, errs.NewValue("x < bottom || m < bottom")
		}
	}
	if a.Cmp(m, a.One()) == algebra.LessThan {
		return nil, errs.NewValue("modulus < 1")
	}
	return B(new(big.Int).Mod(x.Int, m.Int)), nil
}
func (a *BigArithmetic) Min(x, y *BigInt) *BigInt {
	if a.Cmp(x, y) == algebra.LessThan {
		return y
	}
	return x
}
func (a *BigArithmetic) Max(x, y *BigInt) *BigInt {
	if a.Equal(a.Min(x, y), x) {
		return y
	}
	return x
}

func (a *BigArithmetic) Uint64(x *BigInt) uint64 {
	return x.Uint64()
}
