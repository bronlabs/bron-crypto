package uints

import (
	"encoding/binary"
	"math/big"
	"math/bits"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/ct"
)

type U256 struct {
	// if you're thinking about using array or slice here, think twice
	// go is terrible at unrolling loops or optimising random access
	Limb0 uint64
	Limb1 uint64
	Limb2 uint64
	Limb3 uint64
}

var _ UintLike[U256] = U256{}

func NewU256FromBytesLE(value []byte) U256 {
	var result U256
	result.Limb0 = binary.LittleEndian.Uint64(value[(0 * 8):(1 * 8)])
	result.Limb1 = binary.LittleEndian.Uint64(value[(1 * 8):(2 * 8)])
	result.Limb2 = binary.LittleEndian.Uint64(value[(2 * 8):(3 * 8)])
	result.Limb3 = binary.LittleEndian.Uint64(value[(3 * 8):(4 * 8)])

	return result
}

func NewU256FromBytesBE(value []byte) U256 {
	var result U256
	result.Limb3 = binary.BigEndian.Uint64(value[(0 * 8):(1 * 8)])
	result.Limb2 = binary.BigEndian.Uint64(value[(1 * 8):(2 * 8)])
	result.Limb1 = binary.BigEndian.Uint64(value[(2 * 8):(3 * 8)])
	result.Limb0 = binary.BigEndian.Uint64(value[(3 * 8):(4 * 8)])

	return result
}

func NewU256FromNat(nat *saferith.Nat) U256 {
	return NewU256FromBytesBE(nat.FillBytes(make([]byte, 32)))
}

func NewU256FromBig(bint *big.Int) U256 {
	return NewU256FromBytesBE(bint.FillBytes(make([]byte, 32)))
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

func (u U256) Sub(rhs U256) U256 {
	var diff U256
	var borrow uint64
	diff.Limb0, borrow = bits.Sub64(u.Limb0, rhs.Limb0, 0)
	diff.Limb1, borrow = bits.Sub64(u.Limb1, rhs.Limb1, borrow)
	diff.Limb2, borrow = bits.Sub64(u.Limb2, rhs.Limb2, borrow)
	diff.Limb3 = u.Limb3 - rhs.Limb3 - borrow

	return diff
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

func (u U256) Clone() U256 {
	return u
}

func (u U256) IsZero() bool {
	return (u.Limb0 | u.Limb1 | u.Limb2 | u.Limb3) == 0
}

func (u U256) Equals(rhs U256) bool {
	return ((u.Limb0 ^ rhs.Limb0) | (u.Limb1 ^ rhs.Limb1) | (u.Limb2 ^ rhs.Limb2) | (u.Limb3 ^ rhs.Limb3)) == 0
}

func (u U256) Cmp(rhs U256) int {
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

	return 2*geq - eq - 1
}

func (u U256) And(rhs U256) U256 {
	return U256{
		Limb0: u.Limb0 & rhs.Limb0,
		Limb1: u.Limb1 & rhs.Limb1,
		Limb2: u.Limb2 & rhs.Limb2,
		Limb3: u.Limb3 & rhs.Limb3,
	}
}

func (u U256) Or(rhs U256) U256 {
	return U256{
		Limb0: u.Limb0 | rhs.Limb0,
		Limb1: u.Limb1 | rhs.Limb1,
		Limb2: u.Limb2 | rhs.Limb2,
		Limb3: u.Limb3 | rhs.Limb3,
	}
}

func (u U256) Xor(rhs U256) U256 {
	return U256{
		Limb0: u.Limb0 ^ rhs.Limb0,
		Limb1: u.Limb1 ^ rhs.Limb1,
		Limb2: u.Limb2 ^ rhs.Limb2,
		Limb3: u.Limb3 ^ rhs.Limb3,
	}
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

func ConstantTimeU256Select(choice int, lhs, rhs U256) U256 {
	v := uint64(choice)
	vFalse := v - 1
	vTrue := ^vFalse

	return U256{
		Limb0: (vTrue & lhs.Limb0) | (vFalse & rhs.Limb0),
		Limb1: (vTrue & lhs.Limb1) | (vFalse & rhs.Limb1),
		Limb2: (vTrue & lhs.Limb2) | (vFalse & rhs.Limb2),
		Limb3: (vTrue & lhs.Limb3) | (vFalse & rhs.Limb3),
	}
}
