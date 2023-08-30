package uint128

import (
	"encoding/binary"
	"math"
	"math/big"
	"math/bits"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/core/modular"
)

// A Uint128 is an unsigned 128-bit number.
type Uint128 struct {
	Lo, Hi uint64
}

// New returns the Uint128 value (lo,hi).
func New(lo, hi uint64) Uint128 {
	return Uint128{lo, hi}
}

// Clone returns a copy the Uint128 value (lo,hi).
func Clone(num Uint128) Uint128 {
	return Uint128{num.Lo, num.Hi}
}

// Zero|Min are zero-valued uint128. One is the unsigned +1.
var (
	Min  = New(0, 0)
	Zero = New(0, 0)
	One  = New(1, 0)
)

// Max is the largest possible uint128 value.
var Max = New(math.MaxUint64, math.MaxUint64)

// IsZero returns true if u == 0.
func (u Uint128) IsZero() bool {
	return u.Equals(Zero)
}

// Equals returns true if u == v.
func (u Uint128) Equals(v Uint128) bool {
	eqLow := modular.ConstantTimeEq(u.Lo, v.Lo)
	eqHigh := modular.ConstantTimeEq(u.Hi, v.Hi)
	return (eqLow & eqHigh) == 1
}

// BoolToInt converts a boolean value to 0 or 1.
func BoolToInt(b bool) int {
	if b {
		return 1
	} else {
		return 0
	}
}

// Cmp compares u and v and returns:
//
//	-1 if u <  v
//	 0 if u == v
//	+1 if u >  v
func (u Uint128) Cmp(v Uint128) int {
	ltHigh := modular.ConstantTimeGt(v.Hi, u.Hi)
	ltLow := modular.ConstantTimeGt(v.Lo, u.Lo)
	eqHigh := modular.ConstantTimeEq(u.Hi, v.Hi)
	eqLow := modular.ConstantTimeEq(u.Lo, v.Lo)
	return 1 - (eqHigh & eqLow) - 2*(ltHigh|(eqHigh&ltLow))
}

// Cselect returns x if b == true and y if b == false. Inspired by subtle.ConstantTimeSelect().
func Cselect(v bool, x, y Uint128) Uint128 {
	vv := uint64(BoolToInt(v))
	return Uint128{^(vv-1)&x.Lo | (vv-1)&y.Lo, ^(vv-1)&x.Hi | (vv-1)&y.Hi}
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
	hi += u.Hi*v.Lo + u.Lo*v.Hi
	return Uint128{lo, hi}
}

// Lsh returns u<<n.
func (u Uint128) Lsh(n uint) Uint128 {
	Lo_nLeq64 := (u.Lo << n)
	Hi_nLeq64 := (u.Hi<<n | u.Lo>>(64-n))
	Lo_nGt64 := uint64(0)
	Hi_nGt64 := (u.Lo << (n - 64))
	if n > 64 {
		return Uint128{Lo_nGt64, Hi_nGt64}
	} else {
		return Uint128{Lo_nLeq64, Hi_nLeq64}
	}
}

// Rsh returns u>>n.
func (u Uint128) Rsh(n uint) (s Uint128) {
	s_Lo_nLeq64 := (u.Lo>>n | u.Hi<<(64-n))
	s_Hi_nLeq64 := (u.Hi >> n)
	s_Lo_nGt64 := (u.Hi >> (n - 64))
	s_Hi_nGt64 := uint64(0)
	if n > 64 {
		s.Lo = s_Lo_nGt64
		s.Hi = s_Hi_nGt64
	} else {
		s.Lo = s_Lo_nLeq64
		s.Hi = s_Hi_nLeq64
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

// Big returns u as a *big.Int.
func (u Uint128) Big() *big.Int {
	i := new(big.Int).SetUint64(u.Hi)
	i = i.Lsh(i, 64)
	i = i.Xor(i, new(big.Int).SetUint64(u.Lo))
	return i
}

// FromBytesLE converts b to a Uint128 value.
func FromBytesLE(src []byte, dst *Uint128) *Uint128 {
	if dst != nil {
		dst.Lo = binary.LittleEndian.Uint64(src[:8])
		dst.Hi = binary.LittleEndian.Uint64(src[8:])
	} else {
		dst = &Uint128{
			binary.LittleEndian.Uint64(src[:8]),
			binary.LittleEndian.Uint64(src[8:]),
		}
	}
	return dst
}

func FromSaferithNat(src *saferith.Nat, dst *Uint128) *Uint128 {
	if src.AnnouncedLen() > 128 {
		panic("value overflows Uint128")
	}
	srcBytes := src.Bytes()
	if len(srcBytes) < 16 {
		srcBytes = append(make([]byte, 16-len(srcBytes)), srcBytes...)
	}
	if dst != nil {
		dst.Lo = binary.BigEndian.Uint64(srcBytes[8:])
		dst.Hi = binary.BigEndian.Uint64(srcBytes[:8])
	} else {
		dst = &Uint128{
			binary.BigEndian.Uint64(srcBytes[8:]),
			binary.BigEndian.Uint64(srcBytes[:8]),
		}
	}
	return dst
}

func (u Uint128) SaferithNat() *saferith.Nat {
	res := &saferith.Nat{}
	uBytes := make([]byte, 16)
	u.PutBytesBE(uBytes)
	res.SetBytes(uBytes)
	return res
}

// FromBytesBE converts big-endian b to a Uint128 value.
func FromBytesBE(src []byte, dst *Uint128) *Uint128 {
	if dst != nil {
		dst.Lo = binary.BigEndian.Uint64(src[8:])
		dst.Hi = binary.BigEndian.Uint64(src[:8])
	} else {
		dst = &Uint128{
			binary.BigEndian.Uint64(src[8:]),
			binary.BigEndian.Uint64(src[:8]),
		}
	}
	return dst
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
