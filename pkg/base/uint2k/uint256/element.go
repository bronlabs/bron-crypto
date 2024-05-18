package uint256

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"math"
	"math/bits"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/ct"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
)

var (
	Min  = Uint256([4]uint64{0, 0, 0, 0})
	Max  = Uint256([4]uint64{math.MaxUint64, math.MaxUint64, math.MaxUint64, math.MaxUint64})
	Zero = Uint256([4]uint64{0, 0, 0, 0})
	One  = Uint256([4]uint64{1, 0, 0, 0})
)

type Uint256 [4]uint64

var _ integer.Uint[*Ring256, Uint256] = Uint256{}

func (Uint256) AnnouncedLen() int {
	panic("implement me")
}
func (Uint256) TrueLen() uint {
	panic("implement me")
}
func (Uint256) Arithmetic() integer.Arithmetic[Uint256] {
	panic("implement me")
}
func (Uint256) IsBottom() bool {
	panic("implement me")
}
func (Uint256) IsTop() bool {
	panic("implement me")
}
func (Uint256) UpperBoundedLattice() algebra.UpperBoundedOrderTheoreticLattice[*Ring256, Uint256] {
	return Ring()
}
func (Uint256) BoundedLattice() algebra.BoundedOrderTheoreticLattice[*Ring256, Uint256] {
	return Ring()
}
func (Uint256) LowerBoundedLattice() algebra.LowerBoundedOrderTheoreticLattice[*Ring256, Uint256] {
	return Ring()
}

func (Uint256) Structure() *Ring256 {
	return Ring()
}
func (Uint256) Mod(x integer.NaturalSemiRingElement[*Ring256, Uint256]) (Uint256, error) {
	panic("not implemented")
}

func (u Uint256) Equal(v Uint256) bool {
	eqBot := ct.Equal(u[0], v[0])
	eqLo := ct.Equal(u[1], v[1])
	eqHi := ct.Equal(u[2], v[2])
	eqTop := ct.Equal(u[3], v[3])
	return (eqBot & eqLo & eqHi & eqTop) == 1
}

func (u Uint256) Unwrap() Uint256 {
	return u
}

func (u Uint256) Clone() Uint256 {
	return u
}

func (u Uint256) HashCode() uint64 {
	return u[0] ^ u[1] ^ u[2] ^ u[3]
}

func (u Uint256) MarshalJSON() ([]byte, error) {
	serialised, err := json.Marshal([4]uint64(u))
	if err != nil {
		return nil, errs.WrapSerialisation(err, "serialisation failed")
	}

	return serialised, nil
}

func (Uint256) Order(operator algebra.Operator) (*saferith.Nat, error) {
	// TODO implement me
	panic("implement me")
}

func (Uint256) Operate(op algebra.Operator, rhs algebra.GroupoidElement[*Ring256, Uint256]) (Uint256, error) {
	panic("implement me")
}
func (Uint256) IsInvolution(under algebra.Operator) (bool, error) {
	panic("implement me")
}
func (Uint256) IsInvolutionUnderAddition() bool {
	panic("implement me")
}
func (Uint256) IsInvolutionUnderMultiplication() bool {
	panic("implement me")
}
func (Uint256) CanGenerateAllElements(under algebra.Operator) bool {
	panic("implement me")
}

func (Uint256) Apply(operator algebra.Operator, x algebra.GroupoidElement[*Ring256, Uint256], n *saferith.Nat) (Uint256, error) {
	// TODO implement me
	panic("implement me")
}

func (u Uint256) Add(v algebra.AdditiveGroupoidElement[*Ring256, Uint256]) Uint256 {
	var carry uint64
	res := [4]uint64{0, 0, 0, 0}
	rhs := v.Unwrap()

	res[0], carry = bits.Add64(u[0], rhs[0], 0)
	res[1], carry = bits.Add64(u[1], rhs[1], carry)
	res[2], carry = bits.Add64(u[2], rhs[2], carry)
	res[3] = u[3] + rhs[3] + carry
	return res
}

func (u Uint256) ApplyAdd(x algebra.AdditiveGroupoidElement[*Ring256, Uint256], n *saferith.Nat) Uint256 {
	return u.Add(x.Unwrap().Mul(Uint256{}.SetNat(n)))
}

func (u Uint256) Double() Uint256 {
	return [4]uint64{
		u[0] << 1,
		(u[1] << 1) | (u[0] >> 63),
		(u[2] << 1) | (u[1] >> 63),
		(u[3] << 1) | (u[2] >> 63),
	}
}

func (u Uint256) Triple() Uint256 {
	return u.Double().Add(u)
}

func (u Uint256) Mul(v algebra.MultiplicativeGroupoidElement[*Ring256, Uint256]) Uint256 {
	rhs := v.Unwrap()

	var a1, a2, a3, carry uint64
	r := [4]uint64{0, 0, 0, 0}
	r[1], r[0] = bits.Mul64(u[0], rhs[0])
	r[2], a1 = bits.Mul64(u[1], rhs[0])
	carry, r[1] = bits.Add64(r[1], a1, 0)
	r[3], a2 = bits.Mul64(u[2], rhs[0])
	carry, r[2] = bits.Add64(r[2], a2, carry)
	r[3] += carry

	a2, a1 = bits.Mul64(u[0], rhs[1])
	carry, r[1] = bits.Add64(r[1], a1, 0)
	carry, r[2] = bits.Add64(r[2], a2, carry)
	a3, a2 = bits.Mul64(u[1], rhs[1])
	r[3] += a3 + carry
	carry, r[2] = bits.Add64(r[2], a2, 0)
	r[3] += carry

	a3, a2 = bits.Mul64(u[0], rhs[2])
	carry, r[2] = bits.Add64(r[2], a2, 0)
	r[3] += a3 + carry + (u[3]*rhs[0] + u[2]*rhs[1] + u[1]*rhs[2])
	return r
}

func (u Uint256) ApplyMul(x algebra.MultiplicativeGroupoidElement[*Ring256, Uint256], n *saferith.Nat) Uint256 {
	return u.Mul(x.Unwrap().Exp(n))
}

func (u Uint256) Square() Uint256 {
	return u.Mul(u)
}

func (u Uint256) Cube() Uint256 {
	return u.Square().Mul(u)
}

func (u Uint256) Exp(exponent *saferith.Nat) Uint256 {
	u0 := One
	u1 := u
	for j := exponent.AnnouncedLen() - 1; j >= 0; j-- {
		jthBit := exponent.Byte(j/8) & (1 << (j % 8))
		if jthBit == 0 {
			u1 = u0.Mul(u1)
			u0 = u0.Square()
		} else {
			u0 = u0.Mul(u1)
			u1 = u1.Square()
		}
	}

	return u0
}

func (Uint256) IsIdentity(under algebra.Operator) (bool, error) {
	// TODO implement me
	panic("implement me")
}

func (u Uint256) IsAdditiveIdentity() bool {
	return u.IsZero()
}

func (u Uint256) IsMultiplicativeIdentity() bool {
	return u.IsOne()
}

func (u Uint256) MulAdd(p, q algebra.PreSemiRingElement[*Ring256, Uint256]) Uint256 {
	return u.Mul(p).Add(q)
}

func (u Uint256) Cmp(rhs algebra.OrderTheoreticLatticeElement[*Ring256, Uint256]) algebra.Ordering {
	v := rhs.Unwrap()

	gtTop := ct.GreaterThan(u[3], v[3])
	gtHi := ct.GreaterThan(u[2], v[2])
	gtLo := ct.GreaterThan(u[1], v[1])
	gtBot := ct.GreaterThan(u[0], v[0])

	eqTop := ct.Equal(u[3], v[3])
	eqHi := ct.Equal(u[2], v[2])
	eqLo := ct.Equal(u[1], v[1])
	eqBot := ct.Equal(u[0], v[0])

	return algebra.Ordering(-1 + (eqTop & eqHi & eqLo & eqBot) + 2*(gtTop|(eqTop&(gtHi|(eqHi&(gtLo|(eqLo&gtBot)))))))
}

func (u Uint256) Join(rhs algebra.OrderTheoreticLatticeElement[*Ring256, Uint256]) Uint256 {
	return u.Max(rhs.Unwrap())
}

func (u Uint256) Meet(rhs algebra.OrderTheoreticLatticeElement[*Ring256, Uint256]) Uint256 {
	return u.Min(rhs.Unwrap())
}

func (Uint256) Lattice() algebra.OrderTheoreticLattice[*Ring256, Uint256] {
	return Ring()
}

func (u Uint256) Next() (Uint256, error) {
	return u.Add(One), nil
}

func (u Uint256) Previous() (Uint256, error) {
	return u.Sub(One), nil
}

func (u Uint256) Min(rhs algebra.ChainElement[*Ring256, Uint256]) Uint256 {
	return Ring().Select(u.Cmp(rhs) == algebra.LessThan, u, rhs.Unwrap())
}

func (u Uint256) Max(rhs algebra.ChainElement[*Ring256, Uint256]) Uint256 {
	return Ring().Select(u.Cmp(rhs) == algebra.LessThan, rhs.Unwrap(), u)
}

func (Uint256) Chain() algebra.Chain[*Ring256, Uint256] {
	return Ring()
}

func (u Uint256) Increment() Uint256 {
	return u.Add(One)
}

func (u Uint256) Decrement() Uint256 {
	return u.Sub(One)
}

func (u Uint256) Uint64() uint64 {
	return u[0]
}

func (u Uint256) SetNat(src *saferith.Nat) Uint256 {
	srcBytes := src.Bytes()
	dst, err := u.SetBytesWide(srcBytes)
	if err != nil {
		panic(errs.WrapFailed(err, "SetBytesWide should not fail"))
	}
	return dst
}

func (u Uint256) Nat() *saferith.Nat {
	return new(saferith.Nat).SetBytes(u.Bytes())
}

func (u Uint256) IsOne() bool {
	return ((u[0] ^ uint64(1)) | u[1] | u[2] | u[3]) == 0
}

func (u Uint256) IsEven() bool {
	return u[0]&0b1 == 0
}

func (u Uint256) IsOdd() bool {
	return u[0]&0b1 != 0
}

func (u Uint256) IsNonZero() bool {
	return (u[0] | u[1] | u[2] | u[3]) != 0
}

func (u Uint256) IsPositive() bool {
	return u.IsNonZero()
}

// func (Uint256) Int() integer.Int {
// 	// TODO implement me
// 	panic("implement me")
// }

// func (Uint256) FromInt(v integer.Int) Uint256 {
// 	// TODO implement me
// 	panic("implement me")
// }

func (u Uint256) IsZero() bool {
	return (u[0] | u[1] | u[2] | u[3]) == 0
}

func (u Uint256) Not() Uint256 {
	return [4]uint64{
		^u[0],
		^u[1],
		^u[2],
		^u[3],
	}
}

func (u Uint256) And(x algebra.ConjunctiveGroupoidElement[*Ring256, Uint256]) Uint256 {
	rhs := x.Unwrap()

	return [4]uint64{
		u[0] & rhs[0],
		u[1] & rhs[1],
		u[2] & rhs[2],
		u[3] & rhs[3],
	}
}

func (u Uint256) ApplyAnd(x algebra.ConjunctiveGroupoidElement[*Ring256, Uint256], n *saferith.Nat) Uint256 {
	if n.EqZero() != 0 {
		return u
	} else {
		return u.And(x)
	}
}

func (u Uint256) IsConjunctiveIdentity() bool {
	return u.IsZero()
}

func (u Uint256) Or(x algebra.DisjunctiveGroupoidElement[*Ring256, Uint256], ys ...algebra.DisjunctiveGroupoidElement[*Ring256, Uint256]) Uint256 {
	z := u.or(x.Unwrap())
	for _, y := range ys {
		z = z.or(y.Unwrap())
	}

	return z
}

func (u Uint256) or(rhs Uint256) Uint256 {
	return Uint256{
		u[0] | rhs[0],
		u[1] | rhs[1],
		u[2] | rhs[2],
		u[3] | rhs[3],
	}
}

func (u Uint256) ApplyOr(x algebra.DisjunctiveGroupoidElement[*Ring256, Uint256], n *saferith.Nat) Uint256 {
	if n.EqZero() != 0 {
		return u
	} else {
		return u.or(x.Unwrap())
	}
}

func (u Uint256) IsDisjunctiveIdentity() bool {
	return u.IsZero()
}

func (Uint256) Inverse(under algebra.Operator) (Uint256, error) {
	// TODO implement me
	panic("implement me")
}

func (Uint256) IsInverse(of algebra.GroupElement[*Ring256, Uint256], under algebra.Operator) (bool, error) {
	// TODO implement me
	panic("implement me")
}

func (Uint256) IsTorsionElement(order *saferith.Modulus, under algebra.Operator) (bool, error) {
	// TODO implement me
	panic("implement me")
}

func (Uint256) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[*Ring256, Uint256], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[*Ring256, Uint256]) Uint256 {
	z := [4]uint64{0, 0, 0, 0}
	for _, y := range ys {
		z[0] ^= y.Unwrap()[0]
		z[1] ^= y.Unwrap()[1]
		z[2] ^= y.Unwrap()[2]
		z[3] ^= y.Unwrap()[3]
	}

	return z
}

func (u Uint256) ApplyXor(x algebra.ExclusiveDisjunctiveGroupoidElement[*Ring256, Uint256], n *saferith.Nat) Uint256 {
	if (n.Byte(0) & 0b1) == 0 {
		return u
	} else {
		return u.Xor(x)
	}
}

func (u Uint256) IsExclusiveDisjunctiveIdentity() bool {
	return u.IsZero()
}

func (u Uint256) ExclusiveDisjunctiveInverse() Uint256 {
	return u
}

func (u Uint256) IsExclusiveDisjunctiveInverse(of algebra.ExclusiveDisjunctiveGroupElement[*Ring256, Uint256]) bool {
	return u.Xor(of).IsExclusiveDisjunctiveIdentity()
}

func (u Uint256) Lsh(n uint) Uint256 {
	s := [4]uint64{0, 0, 0, 0}

	nLeq64Mask := uint64(0) - uint64(subtle.ConstantTimeLessOrEq(int(n), 64))
	nLeq128Gt64Mask := (uint64(0) - uint64(subtle.ConstantTimeLessOrEq(int(n), 128))) ^ nLeq64Mask
	nLeq192Gt128Mask := (uint64(0) - uint64(subtle.ConstantTimeLessOrEq(int(n), 192))) ^ (nLeq64Mask | nLeq128Gt64Mask)
	s[0] = (u[0] << n) & nLeq64Mask
	s[1] = (u[1] << n) | (u[0]>>(64-n))&nLeq64Mask |
		u[0]<<(n-64)&nLeq128Gt64Mask
	s[2] = (u[2] << n) | (u[1]>>(64-n))&nLeq64Mask |
		(u[1] << (n - 64)) | (u[0]>>(128-n))&nLeq128Gt64Mask |
		(u[0]<<(n-128))&nLeq192Gt128Mask
	s[3] = (u[3] << n) | (u[2]>>(64-n))&nLeq64Mask |
		(u[2] << (n - 64)) | (u[1]>>(128-n))&nLeq128Gt64Mask |
		(u[1] << (n - 128)) | (u[0]>>(192-n))&nLeq192Gt128Mask |
		u[0]<<(n-192)

	return s
}

func (u Uint256) Rsh(n uint) Uint256 {
	s := [4]uint64{0, 0, 0, 0}

	nLeq64Mask := uint64(0) - uint64(subtle.ConstantTimeLessOrEq(int(n), 64))
	nLeq128Gt64Mask := (uint64(0) - uint64(subtle.ConstantTimeLessOrEq(int(n), 128))) ^ nLeq64Mask
	nLeq192Gt128Mask := (uint64(0) - uint64(subtle.ConstantTimeLessOrEq(int(n), 192))) ^ (nLeq64Mask | nLeq128Gt64Mask)
	s[0] = (u[0] >> n) | (u[1]<<(64-n))&nLeq64Mask |
		(u[1] >> (n - 64)) | (u[2]<<(128-n))&nLeq128Gt64Mask |
		(u[2] >> (n - 128)) | (u[3]<<(192-n))&nLeq192Gt128Mask |
		(u[3] >> (n - 192))
	s[1] = (u[1] >> n) | (u[2]<<(64-n))&nLeq64Mask |
		(u[2] >> (n - 64)) | (u[3]<<(128-n))&nLeq128Gt64Mask |
		(u[3]>>(n-128))&nLeq192Gt128Mask
	s[2] = (u[2] >> n) | (u[3]<<(64-n))&nLeq64Mask |
		(u[3]>>(n-64))&nLeq128Gt64Mask
	s[3] = (u[3] >> n) & nLeq64Mask

	return s
}

func (u Uint256) Bytes() []byte {
	b := make([]byte, RingBytes)
	binary.BigEndian.PutUint64(b[:8], u[3])
	binary.BigEndian.PutUint64(b[8:16], u[2])
	binary.BigEndian.PutUint64(b[16:24], u[1])
	binary.BigEndian.PutUint64(b[24:], u[0])
	return b
}

func (Uint256) SetBytes(bytes []byte) (Uint256, error) {
	dst := [4]uint64{0, 0, 0, 0}

	if len(bytes) != RingBytes {
		return Uint256{}, errs.NewLength("length of bytes is %d, should be %d",
			len(bytes), RingBytes)
	}
	dst[3] = binary.BigEndian.Uint64(bytes[:8])
	dst[2] = binary.BigEndian.Uint64(bytes[8:16])
	dst[1] = binary.BigEndian.Uint64(bytes[16:24])
	dst[0] = binary.BigEndian.Uint64(bytes[24:32])
	return dst, nil
}

func (Uint256) SetBytesWide(bytes []byte) (Uint256, error) {
	dst := [4]uint64{0, 0, 0, 0}
	L := len(bytes)
	if L > RingBytes {
		bytes = bytes[L-RingBytes:]
	} else if L < RingBytes {
		bytes = bitstring.PadToLeft(bytes, RingBytes-L)
	}
	dst[3] = binary.BigEndian.Uint64(bytes[:8])
	dst[2] = binary.BigEndian.Uint64(bytes[8:16])
	dst[1] = binary.BigEndian.Uint64(bytes[16:24])
	dst[0] = binary.BigEndian.Uint64(bytes[24:32])
	return dst, nil
}

func (Uint256) BytesLE() []byte {
	// TODO implement me
	panic("implement me")
}

func (Uint256) SetBytesLE(bytes []byte) (Uint256, error) {
	// TODO implement me
	panic("implement me")
}

func (Uint256) SetBytesWideLE(bytes []byte) (Uint256, error) {
	// TODO implement me
	panic("implement me")
}

func (Uint256) AdditiveInverse() Uint256 {
	// TODO implement me
	panic("implement me")
}

func (Uint256) IsAdditiveInverse(of algebra.AdditiveGroupElement[*Ring256, Uint256]) bool {
	// TODO implement me
	panic("implement me")
}

func (Uint256) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	// TODO implement me
	panic("implement me")
}

func (Uint256) Neg() Uint256 {
	// TODO implement me
	panic("implement me")
}

func (u Uint256) Sub(x algebra.AdditiveGroupElement[*Ring256, Uint256]) Uint256 {
	res := Uint256{0, 0, 0, 0}
	rhs := x.Unwrap()

	var borrow uint64
	res[0], borrow = bits.Sub64(u[0], rhs[0], 0)
	res[1], borrow = bits.Sub64(u[1], rhs[1], borrow)
	res[2], borrow = bits.Sub64(u[2], rhs[2], borrow)
	res[3] = u[3] - rhs[3] - borrow
	return res
}

func (u Uint256) ApplySub(x algebra.AdditiveGroupElement[*Ring256, Uint256], n *saferith.Nat) Uint256 {
	return u.Sub(x.Unwrap().Mul(Uint256{}.SetNat(n)))
}

func (Uint256) Sqrt() (Uint256, error) {
	// TODO implement me
	panic("not supported")
}

func (u Uint256) AddUint64(v uint64) (res Uint256) {
	var carry uint64
	res[0], carry = bits.Add64(u[0], v, 0)
	res[1], carry = bits.Add64(u[1], 0, carry)
	res[2], carry = bits.Add64(u[2], 0, carry)
	res[3], _ = bits.Add64(u[3], 0, carry)
	return res
}

func (u Uint256) SubUint64(v uint64) (res Uint256) {
	var borrow uint64
	res[0], borrow = bits.Sub64(u[0], v, 0)
	res[1], borrow = bits.Sub64(u[1], 0, borrow)
	res[2], borrow = bits.Sub64(u[2], 0, borrow)
	res[3], _ = bits.Sub64(u[3], 0, borrow)
	return res
}
