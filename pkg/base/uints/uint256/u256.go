package uint256

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"math/bits"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/ct"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/uints"
)

type U256 struct {
	// if you're thinking about using array or slice here, think twice
	// go is terrible at unrolling loops or optimising random access
	Limb0 uint64
	Limb1 uint64
	Limb2 uint64
	Limb3 uint64
}

var _ algebra.AbstractIntegerRingElement[*Zn, U256] = U256{}
var _ algebra.NatLike[U256] = U256{}
var _ algebra.BytesLike[U256] = U256{}
var _ uints.UintLike[U256] = U256{}

var Zero = U256{
	Limb0: 0,
	Limb1: 0,
	Limb2: 0,
	Limb3: 0,
}

var One = U256{
	Limb0: 1,
	Limb1: 0,
	Limb2: 0,
	Limb3: 0,
}

var Max = U256{
	Limb0: math.MaxUint64,
	Limb1: math.MaxUint64,
	Limb2: math.MaxUint64,
	Limb3: math.MaxUint64,
}

var mod = saferith.ModulusFromNat(new(saferith.Nat).Lsh(new(saferith.Nat).SetUint64(1), 256, 257))

func NewFromBytesLE(value []byte) U256 {
	var buffer [32]byte
	copy(buffer[:], value)

	var result U256
	result.Limb0 = binary.LittleEndian.Uint64(buffer[(0 * 8):(1 * 8)])
	result.Limb1 = binary.LittleEndian.Uint64(buffer[(1 * 8):(2 * 8)])
	result.Limb2 = binary.LittleEndian.Uint64(buffer[(2 * 8):(3 * 8)])
	result.Limb3 = binary.LittleEndian.Uint64(buffer[(3 * 8):(4 * 8)])

	return result
}

func NewFromBytesBE(value []byte) U256 {
	var buffer [32]byte
	if len(value) > 32 {
		copy(buffer[:], value[32-len(value):])
	} else {
		copy(buffer[32-len(value):], value)
	}

	var result U256
	result.Limb3 = binary.BigEndian.Uint64(buffer[(0 * 8):(1 * 8)])
	result.Limb2 = binary.BigEndian.Uint64(buffer[(1 * 8):(2 * 8)])
	result.Limb1 = binary.BigEndian.Uint64(buffer[(2 * 8):(3 * 8)])
	result.Limb0 = binary.BigEndian.Uint64(buffer[(3 * 8):(4 * 8)])

	return result
}

func NewFromNat(nat *saferith.Nat) U256 {
	return NewFromBytesBE(nat.FillBytes(make([]byte, 32)))
}

func (u U256) Equal(e U256) bool {
	return ((u.Limb0 ^ e.Limb0) | (u.Limb1 ^ e.Limb1) | (u.Limb2 ^ e.Limb2) | (u.Limb3 ^ e.Limb3)) == 0
}

func (u U256) Clone() U256 {
	return u
}

func (u U256) HashCode() uint64 {
	return u.Limb0 ^ u.Limb1 ^ u.Limb2 ^ u.Limb3
}

func (u U256) MarshalJSON() ([]byte, error) {
	v := hex.EncodeToString(u.ToBytesBE())
	return json.Marshal(v) //nolint:wrapcheck // forward error
}

func (u U256) Add(rhs U256) U256 {
	var sum U256
	var carry uint64
	sum.Limb0, carry = bits.Add64(u.Limb0, rhs.Limb0, 0)
	sum.Limb1, carry = bits.Add64(u.Limb1, rhs.Limb1, carry)
	sum.Limb2, carry = bits.Add64(u.Limb2, rhs.Limb2, carry)
	sum.Limb3 = u.Limb3 + rhs.Limb3 + carry

	return sum
}

func (u U256) ApplyAdd(x U256, n *saferith.Nat) U256 {
	xx := NewFromNat(n)
	return u.Add(x.Mul(xx))
}

func (u U256) Double() U256 {
	return u.Lsh(1)
}

func (u U256) Triple() U256 {
	return u.Double().Add(u)
}

func (u U256) IsAdditiveIdentity() bool {
	return u.IsZero()
}

func (u U256) AdditiveInverse() U256 {
	return u.Neg()
}

func (u U256) IsAdditiveInverse(of U256) bool {
	return u.Add(of).IsZero()
}

func (u U256) Neg() U256 {
	return U256{
		Limb0: ^u.Limb0,
		Limb1: ^u.Limb1,
		Limb2: ^u.Limb2,
		Limb3: ^u.Limb3,
	}.Add(One)
}

func (u U256) Sub(x U256) U256 {
	var diff U256
	var borrow uint64
	diff.Limb0, borrow = bits.Sub64(u.Limb0, x.Limb0, 0)
	diff.Limb1, borrow = bits.Sub64(u.Limb1, x.Limb1, borrow)
	diff.Limb2, borrow = bits.Sub64(u.Limb2, x.Limb2, borrow)
	diff.Limb3 = u.Limb3 - x.Limb3 - borrow

	return diff
}

func (u U256) ApplySub(x U256, n *saferith.Nat) U256 {
	xx := NewFromNat(n)
	return u.Sub(x.Mul(xx))
}

func (u U256) Mul(rhs U256) U256 {
	u00Hi, u00Lo := bits.Mul64(u.Limb0, rhs.Limb0)
	u01Hi, u01Lo := bits.Mul64(u.Limb0, rhs.Limb1)
	u02Hi, u02Lo := bits.Mul64(u.Limb0, rhs.Limb2)
	u03Lo := u.Limb0 * rhs.Limb3

	u10Hi, u10Lo := bits.Mul64(u.Limb1, rhs.Limb0)
	u11Hi, u11Lo := bits.Mul64(u.Limb1, rhs.Limb1)
	u12Lo := u.Limb1 * rhs.Limb2

	u20Hi, u20Lo := bits.Mul64(u.Limb2, rhs.Limb0)
	u21Lo := u.Limb2 * rhs.Limb1

	u30Lo := u.Limb3 * rhs.Limb0

	var prod U256
	var carry uint64
	prod.Limb0, carry = bits.Add64(prod.Limb0, u00Lo, 0)
	prod.Limb1, carry = bits.Add64(prod.Limb1, u01Lo, carry)
	prod.Limb2, carry = bits.Add64(prod.Limb2, u02Lo, carry)
	prod.Limb3 = prod.Limb3 + u03Lo + carry

	prod.Limb1, carry = bits.Add64(prod.Limb1, u10Lo, 0)
	prod.Limb2, carry = bits.Add64(prod.Limb2, u11Lo, carry)
	prod.Limb3 = prod.Limb3 + u12Lo + carry

	prod.Limb1, carry = bits.Add64(prod.Limb1, u00Hi, 0)
	prod.Limb2, carry = bits.Add64(prod.Limb2, u20Lo, carry)
	prod.Limb3 = prod.Limb3 + u21Lo + carry

	prod.Limb2, carry = bits.Add64(prod.Limb2, u01Hi, 0)
	prod.Limb3 = prod.Limb3 + u30Lo + carry

	prod.Limb2, carry = bits.Add64(prod.Limb2, u10Hi, 0)
	prod.Limb3 = prod.Limb3 + u02Hi + u11Hi + u20Hi + carry

	return prod
}

func (u U256) ApplyMul(x U256, n *saferith.Nat) U256 {
	// fallback to Nat
	rhs := new(saferith.Nat).Exp(x.Nat(), n, mod)
	return u.Mul(NewFromNat(rhs))
}

func (u U256) Square() U256 {
	return u.Mul(u)
}

func (u U256) Cube() U256 {
	return u.Square().Mul(u)
}

func (u U256) IsMultiplicativeIdentity() bool {
	return u.Equal(One)
}

func (u U256) MulAdd(p, q U256) U256 {
	return u.Mul(p).Add(q)
}

func (U256) Sqrt() (U256, error) {
	panic("not implemented")
}

func (u U256) Cmp(rhs U256) algebra.Ordering {
	eq := 1
	geq := 1

	eqAtLimb := ct.Equal(u.Limb0, rhs.Limb0)
	eq &= eqAtLimb
	geq = (eqAtLimb & geq) | ((1 ^ eqAtLimb) & ct.GreaterThan(u.Limb0, rhs.Limb0))

	eqAtLimb = ct.Equal(u.Limb1, rhs.Limb1)
	eq &= eqAtLimb
	geq = (eqAtLimb & geq) | ((1 ^ eqAtLimb) & ct.GreaterThan(u.Limb1, rhs.Limb1))

	eqAtLimb = ct.Equal(u.Limb2, rhs.Limb2)
	eq &= eqAtLimb
	geq = (eqAtLimb & geq) | ((1 ^ eqAtLimb) & ct.GreaterThan(u.Limb2, rhs.Limb2))

	eqAtLimb = ct.Equal(u.Limb3, rhs.Limb3)
	eq &= eqAtLimb
	geq = (eqAtLimb & geq) | ((1 ^ eqAtLimb) & ct.GreaterThan(u.Limb3, rhs.Limb3))

	if (eq & (1 ^ geq)) == 1 {
		panic("eq but not geq")
	}

	return algebra.Ordering(2*geq - eq - 1)
}

func (u U256) Join(rhs U256) U256 {
	return u.Max(rhs)
}

func (u U256) Meet(rhs U256) U256 {
	return u.Min(rhs)
}

func (u U256) IsZero() bool {
	return u.Equal(Zero)
}

func (u U256) IsOne() bool {
	return u.Equal(One)
}

func (u U256) IsEven() bool {
	return u.Limb0^1 == 0
}

func (u U256) IsOdd() bool {
	return u.Limb0^1 != 0
}

func (U256) Increment() {
	panic("not implemented")
}

func (U256) Decrement() {
	panic("not implemented")
}

func (u U256) IsTop() bool {
	return u.Equal(Max)
}

func (u U256) IsBottom() bool {
	return u.Equal(Zero)
}

func (u U256) Min(rhs U256) U256 {
	g := (u.Cmp(rhs) + 1) / 2
	return zn.Select(int(g), u, rhs)
}

func (u U256) Max(rhs U256) U256 {
	g := (u.Cmp(rhs) + 1) / 2
	return zn.Select(int(g), rhs, u)
}

func (u U256) Uint64() uint64 {
	return u.Limb0
}

func (U256) SetNat(v *saferith.Nat) U256 {
	return NewFromNat(v)
}

func (u U256) Bytes() []byte {
	return u.ToBytesBE()
}

func (U256) SetBytes(bytes []byte) (U256, error) {
	if len(bytes) > 32 {
		return U256{}, errs.NewSerialisation("out of range")
	}

	return NewFromBytesBE(bytes), nil
}

func (U256) SetBytesWide(bytes []byte) (U256, error) {
	return NewFromBytesBE(bytes), nil
}

func (u U256) Lsh(shift uint) U256 {
	switch {
	case shift < (1 * 64):
		return U256{
			Limb0: u.Limb0 << shift,
			Limb1: (u.Limb1 << shift) | (u.Limb0 >> (64 - shift)),
			Limb2: (u.Limb2 << shift) | (u.Limb1 >> (64 - shift)),
			Limb3: (u.Limb3 << shift) | (u.Limb2 >> (64 - shift)),
		}
	case shift < (2 * 64):
		return U256{
			Limb0: 0,
			Limb1: u.Limb0 << (shift - 64),
			Limb2: (u.Limb1 << (shift - 64)) | (u.Limb0 >> ((2 * 64) - shift)),
			Limb3: (u.Limb2 << (shift - 64)) | (u.Limb1 >> ((2 * 64) - shift)),
		}
	case shift < (3 * 64):
		return U256{
			Limb0: 0,
			Limb1: 0,
			Limb2: u.Limb0 << (shift - (2 * 64)),
			Limb3: (u.Limb1 << (shift - (2 * 64))) | (u.Limb0 >> ((3 * 64) - shift)),
		}
	default:
		return U256{
			Limb0: 0,
			Limb1: 0,
			Limb2: 0,
			Limb3: u.Limb0 << (shift - (3 * 64)),
		}
	}
}

func (u U256) Rsh(shift uint) U256 {
	switch {
	case shift <= 64:
		return U256{
			Limb0: (u.Limb0 >> shift) | (u.Limb1 << (64 - shift)),
			Limb1: (u.Limb1 >> shift) | (u.Limb2 << (64 - shift)),
			Limb2: (u.Limb2 >> shift) | (u.Limb3 << (64 - shift)),
			Limb3: u.Limb3 >> shift,
		}
	case shift <= (2 * 64):
		return U256{
			Limb0: (u.Limb1 >> (shift - 64)) | (u.Limb2 << ((2 * 64) - shift)),
			Limb1: (u.Limb2 >> (shift - 64)) | (u.Limb3 << ((2 * 64) - shift)),
			Limb2: u.Limb3 >> (shift - 64),
			Limb3: 0,
		}
	case shift <= (3 * 64):
		return U256{
			Limb0: (u.Limb2 >> (shift - (2 * 64))) | (u.Limb3 << ((3 * 64) - shift)),
			Limb1: u.Limb3 >> (shift - (2 * 64)),
			Limb2: 0,
			Limb3: 0,
		}
	default:
		return U256{
			Limb0: u.Limb3 >> (shift - (3 * 64)),
			Limb1: 0,
			Limb2: 0,
			Limb3: 0,
		}
	}
}

func (u U256) And(x U256) U256 {
	return U256{
		Limb0: u.Limb0 & x.Limb0,
		Limb1: u.Limb1 & x.Limb1,
		Limb2: u.Limb2 & x.Limb2,
		Limb3: u.Limb3 & x.Limb3,
	}
}
func (u U256) Or(x U256) U256 {
	return U256{
		Limb0: u.Limb0 | x.Limb0,
		Limb1: u.Limb1 | x.Limb1,
		Limb2: u.Limb2 | x.Limb2,
		Limb3: u.Limb3 | x.Limb3,
	}
}
func (u U256) Xor(x U256) U256 {
	return U256{
		Limb0: u.Limb0 ^ x.Limb0,
		Limb1: u.Limb1 ^ x.Limb1,
		Limb2: u.Limb2 ^ x.Limb2,
		Limb3: u.Limb3 ^ x.Limb3,
	}
}

func (u U256) Not() U256 {
	return U256{
		Limb0: ^u.Limb0,
		Limb1: ^u.Limb1,
		Limb2: ^u.Limb2,
		Limb3: ^u.Limb3,
	}
}
func (u U256) ToBytesLE() []byte {
	var result [32]byte
	binary.LittleEndian.PutUint64(result[(8*0):], u.Limb0)
	binary.LittleEndian.PutUint64(result[(8*1):], u.Limb1)
	binary.LittleEndian.PutUint64(result[(8*2):], u.Limb2)
	binary.LittleEndian.PutUint64(result[(8*3):], u.Limb3)

	return result[:]
}

func (u U256) ToBytesBE() []byte {
	var result [32]byte
	binary.BigEndian.PutUint64(result[(8*0):], u.Limb3)
	binary.BigEndian.PutUint64(result[(8*1):], u.Limb2)
	binary.BigEndian.PutUint64(result[(8*2):], u.Limb1)
	binary.BigEndian.PutUint64(result[(8*3):], u.Limb0)

	return result[:]
}

func (u U256) FillBytesLE(buf []byte) {
	data := u.ToBytesLE()
	copy(buf, data)
}

func (u U256) FillBytesBE(buf []byte) {
	data := u.ToBytesBE()
	if len(buf) > 32 {
		copy(buf[len(buf)-32:], data)
	} else {
		copy(buf, data[32-len(buf):])
	}
}

func (u U256) Nat() *saferith.Nat {
	return new(saferith.Nat).SetBytes(u.ToBytesBE())
}
