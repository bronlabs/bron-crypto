package uint128

import (
	"encoding/binary"
	"math"
	"math/big"
	"math/bits"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
)

type Uint128 struct {
	Lo, Hi uint64
}

var (
	Min  = New(0, 0)
	Max  = New(math.MaxUint64, math.MaxUint64)
	Zero = New(0, 0)
	One  = New(1, 0)
)

// New returns the Uint128 value (lo, hi).
func New(lo, hi uint64) Uint128 {
	return Uint128{lo, hi}
}

// NewFromBytesBE converts big-endian b to the Uint128 value.
func NewFromBytesBE(src []byte) Uint128 {
	var dst Uint128
	dst.Lo = binary.BigEndian.Uint64(src[8:])
	dst.Hi = binary.BigEndian.Uint64(src[:8])
	return dst
}

// NewFromBytesLE converts b to the Uint128 value.
func NewFromBytesLE(src []byte) Uint128 {
	var dst Uint128
	dst.Lo = binary.LittleEndian.Uint64(src[:8])
	dst.Hi = binary.LittleEndian.Uint64(src[8:])
	return dst
}

func NewFromNat(src *saferith.Nat) Uint128 {
	var dst Uint128
	if src.AnnouncedLen() > 128 {
		panic("value overflows Uint128")
	}
	srcBytes := src.Bytes()
	if len(srcBytes) < 16 {
		srcBytes = append(make([]byte, 16-len(srcBytes)), srcBytes...)
	}

	dst.Lo = binary.BigEndian.Uint64(srcBytes[8:])
	dst.Hi = binary.BigEndian.Uint64(srcBytes[:8])
	return dst
}

// Clone returns a copy the Uint128 value (lo, hi).
func (u Uint128) Clone() Uint128 {
	return Uint128{u.Lo, u.Hi}
}

// IsZero returns true if u == 0.
func (u Uint128) IsZero() bool {
	return u.Equals(Zero)
}

// Equals returns true if u == v.
func (u Uint128) Equals(v Uint128) bool {
	eqLow := base.ConstantTimeEq(u.Lo, v.Lo)
	eqHigh := base.ConstantTimeEq(u.Hi, v.Hi)
	return (eqLow & eqHigh) == 1
}

// Cmp compares u and v and returns:
//
//	-1 if u <  v
//	 0 if u == v
//	+1 if u >  v
func (u Uint128) Cmp(v Uint128) int {
	ltHigh := base.ConstantTimeGt(v.Hi, u.Hi)
	ltLow := base.ConstantTimeGt(v.Lo, u.Lo)
	eqHigh := base.ConstantTimeEq(u.Hi, v.Hi)
	eqLow := base.ConstantTimeEq(u.Lo, v.Lo)
	return 1 - (eqHigh & eqLow) - 2*(ltHigh|(eqHigh&ltLow))
}

// And returns u&v.
func (u Uint128) And(v Uint128) Uint128 {
	return Uint128{u.Lo & v.Lo, v.Hi & u.Hi}
}

// Or returns u|v.
func (u Uint128) Or(v Uint128) Uint128 {
	return Uint128{u.Lo | v.Lo, u.Hi | v.Hi}
}

// Xor returns u^v.
func (u Uint128) Xor(v Uint128) Uint128 {
	return Uint128{u.Lo ^ v.Lo, u.Hi ^ v.Hi}
}

// Add returns u+v with wraparound semantics; for example,
// Max.Add(From64(1)) == Zero.
func (u Uint128) Add(v Uint128) Uint128 {
	lo, carry := bits.Add64(u.Lo, v.Lo, 0)
	hi, _ := bits.Add64(u.Hi, v.Hi, carry)
	return Uint128{lo, hi}
}

// Sub returns u-v with wraparound semantics; for example,
// Zero.Sub(From64(1)) == Max.
func (u Uint128) Sub(v Uint128) Uint128 {
	lo, borrow := bits.Sub64(u.Lo, v.Lo, 0)
	hi, _ := bits.Sub64(u.Hi, v.Hi, borrow)
	return Uint128{lo, hi}
}

// Mul returns u*v with wraparound semantics; for example,
// Max.Mul(Max) == 1.
func (u Uint128) Mul(v Uint128) Uint128 {
	hi, lo := bits.Mul64(u.Lo, v.Lo)
	hi += (u.Hi * v.Lo) + (u.Lo * v.Hi)
	return Uint128{lo, hi}
}

// Lsh returns u<<n.
func (u Uint128) Lsh(n uint) Uint128 {
	loNLeq64 := u.Lo << n
	hiNLeq64 := (u.Hi << n) | (u.Lo >> (64 - n))
	loNGt64 := uint64(0)
	hiNGt64 := u.Lo << (n - 64)
	if n > 64 {
		return Uint128{loNGt64, hiNGt64}
	} else {
		return Uint128{loNLeq64, hiNLeq64}
	}
}

// Rsh returns u>>n.
func (u Uint128) Rsh(n uint) (s Uint128) {
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

// PutBytesLE stores u in buffer in little-endian order. It panics if len(buffer) < 16.
func (u Uint128) PutBytesLE(buffer []byte) {
	binary.LittleEndian.PutUint64(buffer[:8], u.Lo)
	binary.LittleEndian.PutUint64(buffer[8:], u.Hi)
}

// PutBytesBE stores u in buffer in big-endian order. It panics if len(buffer) < 16.
func (u Uint128) PutBytesBE(buffer []byte) {
	binary.BigEndian.PutUint64(buffer[:8], u.Hi)
	binary.BigEndian.PutUint64(buffer[8:], u.Lo)
}

func (u Uint128) Nat() *saferith.Nat {
	res := &saferith.Nat{}
	uBytes := make([]byte, 16)
	u.PutBytesBE(uBytes)
	res.SetBytes(uBytes)
	return res
}

// ConstantTimeSelect returns x if b == true or y if b == false. Inspired by subtle.ConstantTimeSelect().
func ConstantTimeSelect(v bool, x, y Uint128) Uint128 {
	vv := uint64(boolToInt(v))
	return Uint128{^(vv-1)&x.Lo | (vv-1)&y.Lo, ^(vv-1)&x.Hi | (vv-1)&y.Hi}
}

// FromBig converts i to a Uint128 value. It panics if i is negative or
// overflows 128 bits.
func FromBig(i *big.Int) (u Uint128) {
	if i.Sign() < 0 {
		panic("value cannot be negative")
	} else if i.BitLen() > 128 {
		panic("value overflows Uint128")
	}
	u.Lo = i.Uint64()
	u.Hi = i.Rsh(i, 64).Uint64()
	return u
}

// boolToInt converts a boolean value to 0 or 1.
func boolToInt(b bool) int {
	if b {
		return 1
	} else {
		return 0
	}
}
