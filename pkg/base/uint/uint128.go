package uint

import (
	"encoding/binary"
	"math"
	"math/big"
	"math/bits"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/ct"
)

type U128 struct {
	Lo, Hi uint64
}

var _ UintLike[U128] = U128{}

var (
	MinU128  = NewU128(0, 0)
	MaxU128  = NewU128(math.MaxUint64, math.MaxUint64)
	ZeroU128 = NewU128(0, 0)
	OneU128  = NewU128(1, 0)
)

// NewU128 returns the U128 value (lo, hi).
func NewU128(lo, hi uint64) U128 {
	return U128{lo, hi}
}

// NewU128FromBytesBE converts big-endian b to the U128 value.
func NewU128FromBytesBE(src []byte) U128 {
	var dst U128
	dst.Lo = binary.BigEndian.Uint64(src[8:])
	dst.Hi = binary.BigEndian.Uint64(src[:8])
	return dst
}

// NewU128FromBytesLE converts b to the U128 value.
func NewU128FromBytesLE(src []byte) U128 {
	var dst U128
	dst.Lo = binary.LittleEndian.Uint64(src[:8])
	dst.Hi = binary.LittleEndian.Uint64(src[8:])
	return dst
}

func NewU128FromNat(src *saferith.Nat) U128 {
	return NewU128FromBytesBE(src.FillBytes(make([]byte, 16)))
}

// NewU128FromBig converts i to a U128 value. It panics if i is negative or
// overflows 128 bits.
func NewU128FromBig(i *big.Int) (u U128) {
	if i.Sign() < 0 {
		panic("value cannot be negative")
	} else if i.BitLen() > 128 {
		panic("value overflows U128")
	}
	u.Lo = i.Uint64()
	u.Hi = i.Rsh(i, 64).Uint64()
	return u
}

// Clone returns a copy the U128 value (lo, hi).
func (u U128) Clone() U128 {
	return U128{u.Lo, u.Hi}
}

// IsZero returns true if u == 0.
func (u U128) IsZero() bool {
	return u.Equals(ZeroU128)
}

// Equals returns true if u == v.
func (u U128) Equals(v U128) bool {
	eqLow := ct.ConstantTimeEq(u.Lo, v.Lo)
	eqHigh := ct.ConstantTimeEq(u.Hi, v.Hi)
	return (eqLow & eqHigh) == 1
}

// Cmp compares u and v and returns:
//
//	-1 if u <  v
//	 0 if u == v
//	+1 if u >  v
func (u U128) Cmp(v U128) int {
	ltHigh := ct.ConstantTimeGt(v.Hi, u.Hi)
	ltLow := ct.ConstantTimeGt(v.Lo, u.Lo)
	eqHigh := ct.ConstantTimeEq(u.Hi, v.Hi)
	eqLow := ct.ConstantTimeEq(u.Lo, v.Lo)
	return 1 - (eqHigh & eqLow) - 2*(ltHigh|(eqHigh&ltLow))
}

// And returns u&v.
func (u U128) And(v U128) U128 {
	return U128{u.Lo & v.Lo, v.Hi & u.Hi}
}

// Or returns u|v.
func (u U128) Or(v U128) U128 {
	return U128{u.Lo | v.Lo, u.Hi | v.Hi}
}

// Xor returns u^v.
func (u U128) Xor(v U128) U128 {
	return U128{u.Lo ^ v.Lo, u.Hi ^ v.Hi}
}

// Add returns u+v with wraparound semantics; for example,
// MaxU128.Add(From64(1)) == ZeroU128.
func (u U128) Add(v U128) U128 {
	lo, carry := bits.Add64(u.Lo, v.Lo, 0)
	hi, _ := bits.Add64(u.Hi, v.Hi, carry)
	return U128{lo, hi}
}

// Sub returns u-v with wraparound semantics; for example,
// ZeroU128.Sub(From64(1)) == MaxU128.
func (u U128) Sub(v U128) U128 {
	lo, borrow := bits.Sub64(u.Lo, v.Lo, 0)
	hi, _ := bits.Sub64(u.Hi, v.Hi, borrow)
	return U128{lo, hi}
}

// Mul returns u*v with wraparound semantics; for example,
// MaxU128.Mul(MaxU128) == 1.
func (u U128) Mul(v U128) U128 {
	hi, lo := bits.Mul64(u.Lo, v.Lo)
	hi += (u.Hi * v.Lo) + (u.Lo * v.Hi)
	return U128{lo, hi}
}

// Lsh returns u<<n.
func (u U128) Lsh(n uint) U128 {
	loNLeq64 := u.Lo << n
	hiNLeq64 := (u.Hi << n) | (u.Lo >> (64 - n))
	loNGt64 := uint64(0)
	hiNGt64 := u.Lo << (n - 64)
	if n > 64 {
		return U128{loNGt64, hiNGt64}
	} else {
		return U128{loNLeq64, hiNLeq64}
	}
}

// Rsh returns u>>n.
func (u U128) Rsh(n uint) (s U128) {
	sLoNLeq64 := (u.Lo >> n) | (u.Hi << (64 - n))
	sHiNLeq64 := u.Hi >> n
	sLoNGt64 := u.Hi >> (n - 64)
	sHiNGt64 := uint64(0)
	if n > 64 {
		s.Lo = sLoNGt64
		s.Hi = sHiNGt64
	} else {
		s.Lo = sLoNLeq64
		s.Hi = sHiNLeq64
	}
	return s
}

func (u U128) Nat() *saferith.Nat {
	return new(saferith.Nat).SetBytes(u.ToBytesBE())
}

func (u U128) ToBytesLE() []byte {
	var result [16]byte
	binary.LittleEndian.PutUint64(result[(8*0):], u.Lo)
	binary.LittleEndian.PutUint64(result[(8*1):], u.Hi)
	return result[:]
}

func (u U128) ToBytesBE() []byte {
	var result [16]byte
	binary.BigEndian.PutUint64(result[(8*0):], u.Hi)
	binary.BigEndian.PutUint64(result[(8*1):], u.Lo)
	return result[:]
}

func (u U128) FillBytesLE(buf []byte) {
	data := u.ToBytesLE()
	copy(buf, data)
}

func (u U128) FillBytesBE(buf []byte) {
	data := u.ToBytesBE()
	if len(buf) >= 16 {
		copy(buf[len(buf)-16:], data)
	} else {
		copy(buf, data[16-len(buf):])
	}
}

// ConstantTimeU128Select returns x if b == true or y if b == false. Inspired by subtle.ConstantTimeSelect().
func ConstantTimeU128Select(choice int, x, y U128) U128 {
	vv := uint64(choice)
	return U128{^(vv-1)&x.Lo | (vv-1)&y.Lo, ^(vv-1)&x.Hi | (vv-1)&y.Hi}
}
