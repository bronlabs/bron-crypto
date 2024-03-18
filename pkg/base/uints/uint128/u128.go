package uint128

import (
	"encoding/binary"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/uints"
	"math"
	"math/big"
	"math/bits"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/ct"
)

type U128 struct {
	Lo, Hi uint64
}

var _ algebra.AbstractIntegerRingElement[*Zn, U128] = U128{}
var _ algebra.NatLike[U128] = U128{}
var _ algebra.BytesLike[U128] = U128{}

var _ uints.UintLike[U128] = U128{}

var (
	Zero = NewU128(0, 0)
	One  = NewU128(1, 0)
	Max  = NewU128(math.MaxUint64, math.MaxUint64)

	mod = saferith.ModulusFromNat(new(saferith.Nat).Lsh(new(saferith.Nat).SetUint64(1), 128, 129))
)

// NewU128 returns the U128 value (lo, hi).
func NewU128(lo, hi uint64) U128 {
	return U128{lo, hi}
}

// NewFromBytesBE converts big-endian b to the U128 value.
func NewFromBytesBE(src []byte) U128 {
	var dst U128
	dst.Lo = binary.BigEndian.Uint64(src[8:])
	dst.Hi = binary.BigEndian.Uint64(src[:8])
	return dst
}

// NewFromBytesLE converts b to the U128 value.
func NewFromBytesLE(src []byte) U128 {
	var dst U128
	dst.Lo = binary.LittleEndian.Uint64(src[:8])
	dst.Hi = binary.LittleEndian.Uint64(src[8:])
	return dst
}

func NewFromNat(src *saferith.Nat) U128 {
	return NewFromBytesBE(src.FillBytes(make([]byte, 16)))
}

// NewFromBig converts i to a U128 value. It panics if i is negative or
// overflows 128 bits.
func NewFromBig(i *big.Int) (u U128) {
	if i.Sign() < 0 {
		panic("value cannot be negative")
	} else if i.BitLen() > 128 {
		panic("value overflows U128")
	}
	u.Lo = i.Uint64()
	u.Hi = i.Rsh(i, 64).Uint64()
	return u
}

func (u U128) HashCode() uint64 {
	return u.Lo ^ u.Hi
}

func (u U128) MarshalJSON() ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (u U128) ApplyAdd(x U128, n *saferith.Nat) U128 {
	return u.Add(x.Mul(NewFromNat(n)))
}

func (u U128) Double() U128 {
	return u.Lsh(1)
}

func (u U128) Triple() U128 {
	return u.Double().Add(u)
}

func (u U128) IsAdditiveIdentity() bool {
	return u.Equal(Zero)
}

func (u U128) AdditiveInverse() U128 {
	return u.Neg()
}

func (u U128) IsAdditiveInverse(of U128) bool {
	return u.Add(of).Equal(Zero)
}

func (u U128) ApplySub(x U128, n *saferith.Nat) U128 {
	return u.Sub(x.Mul(NewFromNat(n)))
}

func (u U128) ApplyMul(x U128, n *saferith.Nat) U128 {
	// fallback to Nat
	rhs := new(saferith.Nat).Exp(x.Nat(), n, mod)
	return u.Mul(NewFromNat(rhs))
}

func (u U128) Square() U128 {
	return u.Mul(u)
}

func (u U128) Cube() U128 {
	return u.Double().Mul(u)
}

func (u U128) IsMultiplicativeIdentity() bool {
	return u.Equal(One)
}

func (u U128) MulAdd(p, q U128) U128 {
	return u.Mul(p).Add(q)
}

func (u U128) Sqrt() (U128, error) {
	//TODO implement me
	panic("implement me")
}

func (u U128) Join(rhs U128) U128 {
	return u.Max(rhs)
}

func (u U128) Meet(rhs U128) U128 {
	return u.Min(rhs)
}

func (u U128) IsOne() bool {
	return u.Equal(One)
}

func (u U128) IsEven() bool {
	return u.Lo&1 == 0
}

func (u U128) IsOdd() bool {
	return u.Lo&1 != 0
}

func (u U128) Neg() U128 {
	return U128{
		Lo: ^u.Lo,
		Hi: ^u.Hi,
	}.Add(One)
}

func (u U128) Increment() {
	panic("not implemented")
}

func (u U128) Decrement() {
	panic("not implemented")
}

func (u U128) IsTop() bool {
	return u.Equal(Max)
}

func (u U128) IsBottom() bool {
	return u.Equal(Zero)
}

func (u U128) Min(rhs U128) U128 {
	//TODO implement me
	panic("implement me")
}

func (u U128) Max(rhs U128) U128 {
	//TODO implement me
	panic("implement me")
}

// Clone returns a copy the U128 value (lo, hi).
func (u U128) Clone() U128 {
	return U128{u.Lo, u.Hi}
}

// IsZero returns true if u == 0.
func (u U128) IsZero() bool {
	return u.Equal(Zero)
}

// Equal returns true if u == v.
func (u U128) Equal(v U128) bool {
	eqLow := ct.Equal(u.Lo, v.Lo)
	eqHigh := ct.Equal(u.Hi, v.Hi)
	return (eqLow & eqHigh) == 1
}

// Cmp compares u and v and returns:
//
//	-1 if u <  v
//	 0 if u == v
//	+1 if u >  v
func (u U128) Cmp(v U128) algebra.Ordering {
	ltHigh := ct.GreaterThan(v.Hi, u.Hi)
	ltLow := ct.GreaterThan(v.Lo, u.Lo)
	eqHigh := ct.Equal(u.Hi, v.Hi)
	eqLow := ct.Equal(u.Lo, v.Lo)
	return algebra.Ordering(1 - (eqHigh & eqLow) - 2*(ltHigh|(eqHigh&ltLow)))
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
// Max.Add(From64(1)) == ZeroU128.
func (u U128) Add(v U128) U128 {
	lo, carry := bits.Add64(u.Lo, v.Lo, 0)
	hi, _ := bits.Add64(u.Hi, v.Hi, carry)
	return U128{lo, hi}
}

// Sub returns u-v with wraparound semantics; for example,
// ZeroU128.Sub(From64(1)) == Max.
func (u U128) Sub(v U128) U128 {
	lo, borrow := bits.Sub64(u.Lo, v.Lo, 0)
	hi, _ := bits.Sub64(u.Hi, v.Hi, borrow)
	return U128{lo, hi}
}

// Mul returns u*v with wraparound semantics; for example,
// Max.Mul(Max) == 1.
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
	if len(buf) > 16 {
		copy(buf[len(buf)-16:], data)
	} else {
		copy(buf, data[16-len(buf):])
	}
}

func (u U128) Uint64() uint64 {
	return u.Lo
}

func (u U128) SetNat(v *saferith.Nat) U128 {
	return NewFromNat(v)
}

func (u U128) Bytes() []byte {
	return u.ToBytesLE()
}

func (u U128) SetBytes(bytes []byte) (U128, error) {
	if len(bytes) > 16 {
		return U128{}, errs.NewSerialisation("out of range")
	}
	var buffer [16]byte
	copy(buffer[:], bytes)
	return NewFromBytesLE(bytes), nil
}

func (u U128) SetBytesWide(bytes []byte) (U128, error) {
	var buffer [16]byte
	copy(buffer[:], bytes)
	return NewFromBytesLE(bytes), nil
}
