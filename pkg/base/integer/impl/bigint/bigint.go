package bigint

import (
	"math/big"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/impl"
	"github.com/cronokirby/saferith"
)

var (
	Zero = big.NewInt(0)
	One  = big.NewInt(1)
	Two  = big.NewInt(2)
)

const Name impl.Name = "BIG_INT"

var _ impl.Number[*BigInt] = (*BigInt)(nil)

type BigInt struct {
	big.Int
}

func (n *BigInt) Unwrap() *BigInt {
	return n
}

func (n *BigInt) Clone() *BigInt {
	return &BigInt{
		Int: *new(big.Int).Set(n.Big()),
	}
}

func (n *BigInt) Big() *big.Int {
	return &n.Int
}

func (n *BigInt) FromBig(v *big.Int) *BigInt {
	return &BigInt{
		Int: *v,
	}
}

func (n *BigInt) Nat() *saferith.Nat {
	return new(saferith.Nat).SetBig(&n.Int, -1)
}

func (n *BigInt) FromNat(v *saferith.Nat) *BigInt {
	return &BigInt{
		Int: *v.Big(),
	}
}

func (n *BigInt) AnnouncedLen() uint {
	return uint(n.BitLen())
}

func (n *BigInt) TrueLen() uint {
	return uint(n.BitLen())
}

var _ impl.Arithmetic[*BigInt] = (*BigArithmetic)(nil)

type BigArithmetic struct {
	bottom  *BigInt
	modulus *BigInt
	size    int
}

func (*BigArithmetic) Name() impl.Name {
	return Name
}

func (a *BigArithmetic) WithoutBottom() impl.Arithmetic[*BigInt] {
	return &BigArithmetic{
		bottom:  nil,
		modulus: nil,
		size:    a.size,
	}
}
func (a *BigArithmetic) WithBottomAtZero() impl.Arithmetic[*BigInt] {
	return &BigArithmetic{
		bottom:  &BigInt{*Zero},
		modulus: a.modulus,
		size:    a.size,
	}
}
func (a *BigArithmetic) WithBottomAtOne() impl.Arithmetic[*BigInt] {
	return &BigArithmetic{
		bottom:  &BigInt{*One},
		modulus: nil,
		size:    a.size,
	}
}
func (a *BigArithmetic) WithBottomAtZeroAndModulus(m *BigInt) impl.Arithmetic[*BigInt] {
	return &BigArithmetic{
		bottom:  &BigInt{*Zero},
		modulus: m,
		size:    a.size,
	}
}
func (a *BigArithmetic) WithSize(size int) impl.Arithmetic[*BigInt] {
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
	return algebra.Ordering(x.Int.Cmp(&y.Int))
}

func (a *BigArithmetic) Zero() *BigInt {
	return &BigInt{*Zero}
}

func (a *BigArithmetic) One() *BigInt {
	return &BigInt{*One}
}

func (a *BigArithmetic) Two() *BigInt {
	return &BigInt{*Two}
}

func (a *BigArithmetic) IsEven(x *BigInt) bool {
	out, _ := a.WithoutBottom().Mod(x, a.Two())
	return a.Cmp(out, a.One()) == algebra.Equal
}

func (a *BigArithmetic) IsOdd(x *BigInt) bool {
	return !a.IsEven(x)
}

func (a *BigArithmetic) Abs(x *BigInt) *BigInt {
	return &BigInt{Int: *new(big.Int).Abs(&x.Int)}
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
	return &BigInt{Int: *new(big.Int).Neg(&x.Int)}, nil
}

func (a *BigArithmetic) Inverse(x *BigInt) (*BigInt, error) {
	if a.bottom != nil && a.Cmp(x, a.bottom) == algebra.LessThan {
		return nil, errs.NewValue("x < bottom")
	}
	if a.Cmp(x, a.Zero()) == algebra.Equal {
		return nil, errs.NewValue("x == 0")
	}
	if a.modulus != nil {
		return &BigInt{Int: *new(big.Int).ModInverse(&x.Int, &a.modulus.Int)}, nil
	}
	return &BigInt{Int: *new(big.Int).Div(&a.One().Int, &x.Int)}, nil
}

func (a *BigArithmetic) Add(x, y *BigInt) (*BigInt, error) {
	xy := &BigInt{Int: *new(big.Int).Add(&x.Int, &y.Int)}
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
	xy := &BigInt{Int: *new(big.Int).Sub(&x.Int, &y.Int)}
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
	xy := &BigInt{Int: *new(big.Int).Mul(&x.Int, &y.Int)}
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
	if a.modulus != nil {
		return &BigInt{Int: *new(big.Int).Exp(&x.Int, &y.Int, &a.modulus.Int)}, nil
	}
	return &BigInt{Int: *new(big.Int).Exp(&x.Int, &y.Int, nil)}, nil
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
	return &BigInt{Int: *new(big.Int).Mod(&x.Int, &m.Int)}, nil
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
