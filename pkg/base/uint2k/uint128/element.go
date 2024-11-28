package uint128

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"math"
	"math/big"
	"math/bits"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/ct"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils/safecast"
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
	return u.Equal(Zero)
}

// Equal returns true if u == v.
func (u Uint128) Equal(v Uint128) bool {
	eqLow := ct.Equal(u.Lo, v.Lo)
	eqHigh := ct.Equal(u.Hi, v.Hi)
	return eqLow&eqHigh == 1
}

// Lsh returns u<<n.

// Rsh returns u>>n.

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
	vv := safecast.MustToUint64(utils.BoolTo[int](v))
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

var _ algebra.IntegerRingElement[*Ring128, Uint128] = Uint128{}

func (Uint128) Structure() *Ring128 {
	return Ring()
}

func (u Uint128) Unwrap() Uint128 {
	return u
}

func (u Uint128) HashCode() uint64 {
	return u.Lo ^ u.Hi
}

func (u Uint128) MarshalJSON() ([]byte, error) {
	tmp := [2]uint64{u.Lo, u.Hi}
	serialised, err := json.Marshal(tmp)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot serialise u128")
	}

	return serialised, nil
}

func (Uint128) Order(operator algebra.BinaryOperator[Uint128]) (*saferith.Modulus, error) {
	// TODO implement me
	panic("implement me")
}

func (Uint128) ApplyOp(operator algebra.BinaryOperator[Uint128], x algebra.GroupoidElement[*Ring128, Uint128], n *saferith.Nat) (Uint128, error) {
	// TODO implement me
	panic("implement me")
}

func (u Uint128) Add(rhs algebra.AdditiveGroupoidElement[*Ring128, Uint128]) Uint128 {
	v := rhs.Unwrap()
	lo, carry := bits.Add64(u.Lo, v.Lo, 0)
	hi := u.Hi + v.Hi + carry
	return Uint128{lo, hi}
}

func (u Uint128) ApplyAdd(x algebra.AdditiveGroupoidElement[*Ring128, Uint128], n *saferith.Nat) Uint128 {
	return u.Add(x.Unwrap().Mul(Uint128{}.SetNat(n)))
}

func (u Uint128) Double() Uint128 {
	return Uint128{
		Lo: u.Lo << 1,
		Hi: (u.Hi << 1) | (u.Lo >> (64 - 1)),
	}
}

func (u Uint128) Triple() Uint128 {
	return u.Double().Add(u)
}

func (u Uint128) Mul(rhs algebra.MultiplicativeGroupoidElement[*Ring128, Uint128]) Uint128 {
	v := rhs.Unwrap()
	hi, lo := bits.Mul64(u.Lo, v.Lo)
	hi += (u.Hi * v.Lo) + (u.Lo * v.Hi)
	return Uint128{lo, hi}
}

func (u Uint128) ApplyMul(x algebra.MultiplicativeGroupoidElement[*Ring128, Uint128], n *saferith.Nat) Uint128 {
	return u.Mul(x.Exp(n))
}

func (u Uint128) Square() Uint128 {
	return u.Mul(u)
}

func (u Uint128) Cube() Uint128 {
	return u.Square().Mul(u)
}

func (u Uint128) Exp(exponent *saferith.Nat) Uint128 {
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

func (Uint128) IsIdentity(under algebra.BinaryOperator[Uint128]) (bool, error) {
	// TODO implement me
	panic("implement me")
}

func (u Uint128) IsAdditiveIdentity() bool {
	return u.IsZero()
}

func (u Uint128) IsMultiplicativeIdentity() bool {
	return u.IsOne()
}

func (u Uint128) MulAdd(p, q algebra.RingElement[*Ring128, Uint128]) Uint128 {
	return u.Mul(p).Add(q)
}

//nolint:gosec // disable G115
func (u Uint128) Cmp(rhs algebra.OrderTheoreticLatticeElement[*Ring128, Uint128]) algebra.Ordering {
	v := rhs.Unwrap()
	ltHigh := ct.Greater(v.Hi, u.Hi)
	ltLow := ct.Greater(v.Lo, u.Lo)
	eqHigh := ct.Equal(u.Hi, v.Hi)
	eqLow := ct.Equal(u.Lo, v.Lo)
	return algebra.Ordering(1 - (eqHigh & eqLow) - 2*(ltHigh|(eqHigh&ltLow)))
}

func (u Uint128) Join(rhs algebra.OrderTheoreticLatticeElement[*Ring128, Uint128]) Uint128 {
	return u.Max(rhs.Unwrap())
}

func (u Uint128) Meet(rhs algebra.OrderTheoreticLatticeElement[*Ring128, Uint128]) Uint128 {
	return u.Min(rhs.Unwrap())
}

func (Uint128) Lattice() algebra.OrderTheoreticLattice[*Ring128, Uint128] {
	return Ring()
}

func (u Uint128) Next() (Uint128, error) {
	return u.Increment(), nil
}

func (u Uint128) Previous() (Uint128, error) {
	return u.Decrement(), nil
}

func (u Uint128) Min(rhs Uint128) Uint128 {
	lt := safecast.MustToUint64(subtle.ConstantTimeEq(safecast.MustToInt32(u.Cmp(rhs)), safecast.MustToInt32(algebra.LessThan)))
	return Ring().Select(lt, u, rhs)
}

func (u Uint128) Max(rhs Uint128) Uint128 {
	lt := safecast.MustToUint64(subtle.ConstantTimeEq(safecast.MustToInt32(u.Cmp(rhs)), safecast.MustToInt32(algebra.LessThan)))
	return Ring().Select(lt, rhs, u)
}

func (Uint128) Chain() algebra.Chain[*Ring128, Uint128] {
	return Ring()
}

func (u Uint128) Increment() Uint128 {
	return u.Add(One)
}

func (u Uint128) Decrement() Uint128 {
	return u.Sub(One)
}

func (u Uint128) Uint64() uint64 {
	return u.Lo
}

func (u Uint128) SetNat(src *saferith.Nat) Uint128 {
	srcBytes := src.Bytes()
	dst, err := u.SetBytesWide(srcBytes)
	if err != nil {
		panic(errs.WrapFailed(err, "SetBytesWide should not fail"))
	}
	return dst
}

func (u Uint128) IsOne() bool {
	return ((u.Lo ^ 0b1) | u.Hi) == 0
}

func (u Uint128) IsEven() bool {
	return (u.Lo & 0b1) == 0
}

func (u Uint128) IsOdd() bool {
	return (u.Lo & 0b1) != 0
}

func (u Uint128) IsNonZero() bool {
	return (u.Lo | u.Hi) != 0
}

func (u Uint128) IsPositive() bool {
	return u.IsNonZero()
}

func (Uint128) Int() algebra.Int {
	// TODO implement me
	panic("implement me")
}

func (Uint128) FromInt(v algebra.Int) Uint128 {
	// TODO implement me
	panic("implement me")
}

func (u Uint128) Not() Uint128 {
	return Uint128{Lo: ^u.Lo, Hi: ^u.Hi}
}

func (u Uint128) And(x algebra.ConjunctiveGroupoidElement[*Ring128, Uint128]) Uint128 {
	rhs := x.Unwrap()
	return Uint128{
		Lo: u.Lo & rhs.Lo,
		Hi: u.Hi & rhs.Hi,
	}
}

func (u Uint128) ApplyAnd(x algebra.ConjunctiveGroupoidElement[*Ring128, Uint128], n *saferith.Nat) Uint128 {
	if n.EqZero() != 0 {
		return u
	} else {
		return u.And(x)
	}
}

func (u Uint128) IsConjunctiveIdentity() bool {
	return ((u.Lo ^ math.MaxUint64) | (u.Hi ^ math.MaxUint64)) == 0
}

func (u Uint128) Or(x algebra.DisjunctiveGroupoidElement[*Ring128, Uint128], ys ...algebra.DisjunctiveGroupoidElement[*Ring128, Uint128]) Uint128 {
	z := u.or(x.Unwrap())
	for _, y := range ys {
		z = z.or(y.Unwrap())
	}

	return z
}

func (u Uint128) or(v Uint128) Uint128 {
	return Uint128{u.Lo | v.Lo, u.Hi | v.Hi}
}

func (u Uint128) ApplyOr(x algebra.DisjunctiveGroupoidElement[*Ring128, Uint128], n *saferith.Nat) Uint128 {
	if n.EqZero() != 0 {
		return u
	} else {
		return u.or(x.Unwrap())
	}
}

func (u Uint128) IsDisjunctiveIdentity() bool {
	return u.IsZero()
}

func (Uint128) Inverse(under algebra.BinaryOperator[Uint128]) (Uint128, error) {
	// TODO implement me
	panic("implement me")
}

func (Uint128) IsInverse(of algebra.GroupElement[*Ring128, Uint128], under algebra.BinaryOperator[Uint128]) (bool, error) {
	// TODO implement me
	panic("implement me")
}

func (Uint128) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[Uint128]) (bool, error) {
	// TODO implement me
	panic("implement me")
}

func (u Uint128) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[*Ring128, Uint128], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[*Ring128, Uint128]) Uint128 {
	z := u.xor(x.Unwrap())
	for _, y := range ys {
		z = z.xor(y.Unwrap())
	}

	return z
}

func (u Uint128) xor(v Uint128) Uint128 {
	return Uint128{u.Lo ^ v.Lo, u.Hi ^ v.Hi}
}

func (u Uint128) ApplyXor(x algebra.ExclusiveDisjunctiveGroupoidElement[*Ring128, Uint128], n *saferith.Nat) Uint128 {
	if n.Byte(0)&0b1 != 0 {
		return u.xor(x.Unwrap())
	} else {
		return u
	}
}

func (u Uint128) IsExclusiveDisjunctiveIdentity() bool {
	return u.IsZero()
}

func (u Uint128) ExclusiveDisjunctiveInverse() Uint128 {
	return u
}

func (u Uint128) IsExclusiveDisjunctiveInverse(of algebra.ExclusiveDisjunctiveGroupElement[*Ring128, Uint128]) bool {
	return u.xor(of.Unwrap()).IsExclusiveDisjunctiveIdentity()
}

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

func (u Uint128) Rsh(n uint) Uint128 {
	s := Uint128{
		Lo: 0,
		Hi: 0,
	}

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

func (Uint128) Bytes() []byte {
	// TODO implement me
	panic("implement me")
}

func (Uint128) SetBytes(bytes []byte) (Uint128, error) {
	// TODO implement me
	panic("implement me")
}

func (Uint128) SetBytesWide(bytes []byte) (Uint128, error) {
	// TODO implement me
	panic("implement me")
}

func (Uint128) BytesLE() []byte {
	// TODO implement me
	panic("implement me")
}

func (Uint128) SetBytesLE(bytes []byte) (Uint128, error) {
	// TODO implement me
	panic("implement me")
}

func (Uint128) SetBytesWideLE(bytes []byte) (Uint128, error) {
	// TODO implement me
	panic("implement me")
}

func (u Uint128) AdditiveInverse() Uint128 {
	return Zero.Sub(u)
}

func (u Uint128) IsAdditiveInverse(of algebra.AdditiveGroupElement[*Ring128, Uint128]) bool {
	return u.Add(of.Unwrap()).IsAdditiveIdentity()
}

func (Uint128) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	// TODO implement me
	panic("implement me")
}

func (u Uint128) Neg() Uint128 {
	return Uint128{
		Lo: ^u.Lo,
		Hi: ^u.Hi,
	}
}

func (u Uint128) Sub(x algebra.AdditiveGroupElement[*Ring128, Uint128]) Uint128 {
	v := x.Unwrap()
	lo, borrow := bits.Sub64(u.Lo, v.Lo, 0)
	hi, _ := bits.Sub64(u.Hi, v.Hi, borrow)
	return Uint128{lo, hi}
}

func (u Uint128) ApplySub(x algebra.AdditiveGroupElement[*Ring128, Uint128], n *saferith.Nat) Uint128 {
	return u.Sub(x.Unwrap().Mul(Uint128{}.SetNat(n)))
}

func (u Uint128) IsQuadraticResidue() bool {
	_, err := u.Sqrt()
	return err != nil
}

func (Uint128) Sqrt() (Uint128, error) {
	// TODO implement me
	panic("implement me")
}
