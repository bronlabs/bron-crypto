package u256

import (
	"encoding/binary"
	"math/bits"
)

type U256 struct {
	// if you're thinking about using array or slice here, think twice
	// go is terrible at unrolling loops or optimising random access
	Limb0 uint64
	Limb1 uint64
	Limb2 uint64
	Limb3 uint64
}

func NewFromBytesLe(value []byte) U256 {
	var result U256
	result.Limb0 = binary.LittleEndian.Uint64(value[(0 * 8):(1 * 8)])
	result.Limb1 = binary.LittleEndian.Uint64(value[(1 * 8):(2 * 8)])
	result.Limb2 = binary.LittleEndian.Uint64(value[(2 * 8):(3 * 8)])
	result.Limb3 = binary.LittleEndian.Uint64(value[(3 * 8):(4 * 8)])

	return result
}

func (u U256) Add(rhs U256) U256 {
	var sum U256
	var carry uint64
	sum.Limb0, carry = bits.Add64(u.Limb0, rhs.Limb0, 0)
	sum.Limb1, carry = bits.Add64(u.Limb1, rhs.Limb1, carry)
	sum.Limb2, carry = bits.Add64(u.Limb2, rhs.Limb2, carry)
	sum.Limb3, carry = bits.Add64(u.Limb3, rhs.Limb3, carry)

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

func (u U256) ToBytesLe() []byte {
	var result [32]byte
	binary.LittleEndian.PutUint64(result[(8*0):], u.Limb0)
	binary.LittleEndian.PutUint64(result[(8*1):], u.Limb1)
	binary.LittleEndian.PutUint64(result[(8*2):], u.Limb2)
	binary.LittleEndian.PutUint64(result[(8*3):], u.Limb3)

	return result[:]
}
