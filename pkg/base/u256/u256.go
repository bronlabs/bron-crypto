package u256

import (
	"encoding/binary"
	"math/bits"
)

const (
	// offset must be > 1 so limb subtraction doesn't overflow.
	offset = 2

	// shift defines a number of bits to keep in one limb
	// keep this a multiple of 8 to have a fast to toBytes/fromBytes operations.
	shiftBytes = 7
	shift      = 8 * shiftBytes
	mask       = (1 << shift) - 1
)

type U256 struct {
	// u256 = limb0 * 2^(56^0) + limb1 * 2^(56^1) + ... + limb4 * 2^(56^4)
	// if you're thinking about using array of slice here, think twice
	// go is terrible at unrolling loops or optimising random access
	Limb0 uint64
	Limb1 uint64
	Limb2 uint64
	Limb3 uint64
	Limb4 uint64
}

func NewFromBytesLe(value []byte) U256 {
	l0 := binary.LittleEndian.Uint64(append(append(make([]byte, 0), value[:shiftBytes]...), 0))
	l1 := binary.LittleEndian.Uint64(append(append(make([]byte, 0), value[shiftBytes:(2*shiftBytes)]...), 0))
	l2 := binary.LittleEndian.Uint64(append(append(make([]byte, 0), value[(2*shiftBytes):(3*shiftBytes)]...), 0))
	l3 := binary.LittleEndian.Uint64(append(append(make([]byte, 0), value[(3*shiftBytes):(4*shiftBytes)]...), 0))
	l4 := uint64(binary.LittleEndian.Uint32(value[(4 * shiftBytes):]))

	var result U256
	result.Limb0 = l0
	result.Limb1 = l1
	result.Limb2 = l2
	result.Limb3 = l3
	result.Limb4 = l4
	return result
}

func (u U256) Add(rhs U256) U256 {
	// input and output invariant: limbX < 0x02000000_00000000

	l0 := u.Limb0 + rhs.Limb0
	l1 := u.Limb1 + rhs.Limb1
	l2 := u.Limb2 + rhs.Limb2
	l3 := u.Limb3 + rhs.Limb3
	l4 := u.Limb4 + rhs.Limb4

	var sum U256
	sum.Limb0 = l0 & mask
	sum.Limb1 = l1&mask + l0>>shift
	sum.Limb2 = l2&mask + l1>>shift
	sum.Limb3 = l3&mask + l2>>shift
	sum.Limb4 = l4 + l3>>shift
	return sum
}

func (u U256) Sub(rhs U256) U256 {
	// input and output invariant: limbX < 0x02000000_00000000

	// borrow 58-th bit from higher limb so subtraction doesn't overflow)
	l0 := u.Limb0 - rhs.Limb0 + (1 << (shift + offset))
	l1 := u.Limb1 - rhs.Limb1 + (1 << (shift + offset)) - (1 << offset)
	l2 := u.Limb2 - rhs.Limb2 + (1 << (shift + offset)) - (1 << offset)
	l3 := u.Limb3 - rhs.Limb3 + (1 << (shift + offset)) - (1 << offset)
	l4 := u.Limb4 - rhs.Limb4 - (1 << offset) // ok to overflow

	var diff U256
	diff.Limb0 = l0 & mask
	diff.Limb1 = l1&mask + l0>>shift
	diff.Limb2 = l2&mask + l1>>shift
	diff.Limb3 = l3&mask + l2>>shift
	diff.Limb4 = l4 + l3>>shift
	return diff
}

func (u U256) Mul(rhs U256) U256 {
	// input and output invariant: limbX < 0x02000000_00000000

	hi, lo := bits.Mul64(u.Limb0, rhs.Limb0)
	u00Hi, u00Lo := (hi<<(64-shift))+(lo>>shift), lo&mask
	hi, lo = bits.Mul64(u.Limb0, rhs.Limb1)
	u01Hi, u01Lo := (hi<<(64-shift))+(lo>>shift), lo&mask
	hi, lo = bits.Mul64(u.Limb0, rhs.Limb2)
	u02Hi, u02Lo := (hi<<(64-shift))+(lo>>shift), lo&mask
	hi, lo = bits.Mul64(u.Limb0, rhs.Limb3)
	u03Hi, u03Lo := (hi<<(64-shift))+(lo>>shift), lo&mask
	u04Lo := u.Limb0 * rhs.Limb4

	hi, lo = bits.Mul64(u.Limb1, rhs.Limb0)
	u10Hi, u10Lo := (hi<<(64-shift))+(lo>>shift), lo&mask
	hi, lo = bits.Mul64(u.Limb1, rhs.Limb1)
	u11Hi, u11Lo := (hi<<(64-shift))+(lo>>shift), lo&mask
	hi, lo = bits.Mul64(u.Limb1, rhs.Limb2)
	u12Hi, u12Lo := (hi<<(64-shift))+(lo>>shift), lo&mask
	u13Lo := u.Limb1 * rhs.Limb3

	hi, lo = bits.Mul64(u.Limb2, rhs.Limb0)
	u20Hi, u20Lo := (hi<<(64-shift))+(lo>>shift), lo&mask
	hi, lo = bits.Mul64(u.Limb2, rhs.Limb1)
	u21Hi, u21Lo := (hi<<(64-shift))+(lo>>shift), lo&mask
	u22Lo := u.Limb2 * rhs.Limb2

	hi, lo = bits.Mul64(u.Limb3, rhs.Limb0)
	u30Hi, u30Lo := (hi<<(64-shift))+(lo>>shift), lo&mask
	u31Lo := u.Limb3 * rhs.Limb1

	u40Lo := u.Limb4 * rhs.Limb0

	l0 := u00Lo
	l1 := u01Lo + u10Lo + u00Hi
	l2 := u02Lo + u11Lo + u20Lo + u01Hi + u10Hi
	l3 := u03Lo + u12Lo + u21Lo + u30Lo + u02Hi + u11Hi + u20Hi                 // < 0x0C000000_00000000
	l4 := u40Lo + u31Lo + u22Lo + u13Lo + u04Lo + u03Hi + u12Hi + u21Hi + u30Hi // ok to overflow

	var prod U256
	prod.Limb0 = l0 & mask
	prod.Limb1 = l1&mask + l0>>shift
	prod.Limb2 = l2&mask + l1>>shift
	prod.Limb3 = l3&mask + l2>>shift
	prod.Limb4 = l4&mask + l3>>shift
	return prod
}

func (u U256) ToBytesLe() []byte {
	reduced := u.reduce()

	var result [32]byte
	binary.LittleEndian.PutUint64(result[:], reduced.Limb0)
	binary.LittleEndian.PutUint64(result[shiftBytes:], reduced.Limb1)
	binary.LittleEndian.PutUint64(result[(shiftBytes*2):], reduced.Limb2)
	binary.LittleEndian.PutUint64(result[(shiftBytes*3):], reduced.Limb3)
	binary.LittleEndian.PutUint32(result[(shiftBytes*4):], uint32(reduced.Limb4))
	return result[:]
}

func (u U256) reduce() U256 {
	l0 := u.Limb0
	c1 := l0 >> shift
	l1 := u.Limb1 + c1
	c2 := l1 >> shift
	l2 := u.Limb2 + c2
	c3 := l2 >> shift
	l3 := u.Limb3 + c3
	c4 := l3 >> shift
	l4 := u.Limb4 + c4

	var reduced U256
	reduced.Limb0 = l0 & mask
	reduced.Limb1 = l1 & mask
	reduced.Limb2 = l2 & mask
	reduced.Limb3 = l3 & mask
	reduced.Limb4 = l4 & mask
	return reduced
}
