package uint256

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"math"
	"math/big"
	"math/bits"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/ct"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/uint2k"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

const (
	Name      = "uint%s"
	RingBits  = 256
	RingBytes = RingBits / 8
)

var (
	ring256InitOnce sync.Once
	ring256Instance *Ring256

	mod2Pow256 = saferith.ModulusFromNat(new(saferith.Nat).Lsh(new(saferith.Nat).SetUint64(1), RingBits, -1))
)

var _ uint2k.Ring2k[*Ring256, Uint256] = (*Ring256)(nil)

// Ring256 is a ring ℤ/2^256ℤ of integers modulo 2^256.
type Ring256 struct {
	_ ds.Incomparable
}

var (
	minUint256 = Uint256{0, 0, 0, 0}
	max        = New(math.MaxUint64, math.MaxUint64, math.MaxUint64, math.MaxUint64)
	zero       = Uint256{0, 0, 0, 0}
	one        = Uint256{1, 0, 0, 0}
)

// Uint256 represents a 256-bit unsigned integer, stored as a 4-limb little-endian
// number (bot, lo, hi, top).
type Uint256 [4]uint64

/*.--------------------------------------------------------------------------.*/
/*.-------------------------------- Ring256 ---------------------------------.*/
/*.--------------------------------------------------------------------------.*/

func ring256Init() {
	ring256Instance = &Ring256{}
}

func Ring() *Ring256 {
	ring256InitOnce.Do(ring256Init)
	return ring256Instance
}

// === Basic Methods.

func (*Ring256) Name() string {
	return Name
}

func (*Ring256) Element() Uint256 {
	return Uint256{}
}

func (*Ring256) Order() *saferith.Modulus {
	return mod2Pow256
}

func (*Ring256) Operators() []algebra.Operator {
	return []algebra.Operator{algebra.Addition, algebra.Multiplication}
}

func (r *Ring256) OperateOver(operator algebra.Operator, xs ...Uint256) (res Uint256, err error) {
	switch operator {
	case algebra.Addition:
		res = r.Identity()
		for _, p := range xs {
			res = res.Add(p)
		}
	case algebra.Multiplication:
		res = r.MultiplicativeIdentity()
		for _, p := range xs {
			res = res.Mul(p)
		}
	case algebra.PointAddition:
		return Uint256{}, errs.NewFailed("PointAddition not supported")
	default:
		return Uint256{}, errs.NewFailed("unsupported operator (%d)", operator)
	}
	return res, nil
}

func (*Ring256) Random(prng io.Reader) (dst Uint256, err error) {
	if prng == nil {
		return Uint256{}, errs.NewIsNil("nil prng")
	}
	var buf [RingBytes]byte
	if _, err := io.ReadFull(prng, buf[:]); err != nil {
		return Uint256{}, errs.WrapRandomSample(err, "failed to read random Uint256")
	}
	dst, err = zero.SetBytesWide(buf[:])
	if err != nil {
		panic(errs.WrapFailed(err, "this should never happen"))
	}
	return dst, nil
}

func (*Ring256) Hash(x []byte) (dst Uint256, err error) {
	buf, err := hashing.Hash(base.RandomOracleHashFunction, x)
	if err != nil {
		return Uint256{}, errs.WrapHashing(err, "failed to hash Uint256")
	}
	dst, err = zero.SetBytesWide(buf)
	if err != nil {
		panic(errs.WrapFailed(err, "this should never happen"))
	}
	return dst, nil
}

func (*Ring256) Select(v bool, x, y Uint256) Uint256 {
	b := utils.BoolTo[uint64](v)
	return Uint256{
		^(b-1)&x[0] | (b-1)&y[0], ^(b-1)&x[1] | (b-1)&y[1],
		^(b-1)&x[2] | (b-1)&y[2], ^(b-1)&x[3] | (b-1)&y[3],
	}
}

// === Additive Groupoid Methods.

func (*Ring256) Add(x Uint256, ys ...Uint256) Uint256 {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum
}

// === Monoid Methods.

func (*Ring256) Identity() Uint256 {
	return Uint256{}
}

// === Additive Monoid Methods.

func (r *Ring256) AdditiveIdentity() Uint256 {
	return r.Identity()
}

// === AdditiveGroup Methods.

func (*Ring256) Sub(x Uint256, ys ...Uint256) Uint256 {
	res := x
	for _, y := range ys {
		res = res.Sub(y)
	}
	return res
}

// === Multiplicative Groupoid Methods.

func (*Ring256) Multiply(x Uint256, ys ...Uint256) Uint256 {
	res := x
	for _, y := range ys {
		res = res.Mul(y)
	}
	return res
}

// === Multiplicative Monoid Methods.

func (*Ring256) MultiplicativeIdentity() Uint256 {
	return Uint256{1, 0, 0, 0}
}

// === Ring Methods.

func (*Ring256) QuadraticResidue(p Uint256) (Uint256, error) {
	panic("not implemented")
}

func (*Ring256) Characteristic() *saferith.Nat {
	return mod2Pow256.Nat()
}

// === Lattice Methods.

func (*Ring256) Join(x, y Uint256) Uint256 {
	return x.Join(y)
}

func (*Ring256) Meet(x, y Uint256) Uint256 {
	return x.Meet(y)
}

// === Z Methods.

func (*Ring256) New(v uint64) Uint256 {
	return Uint256{v, 0, 0, 0}
}

func (*Ring256) Zero() Uint256 {
	return Uint256{}
}

func (*Ring256) One() Uint256 {
	return Uint256{1, 0, 0, 0}
}

// === Zn Methods.

func (*Ring256) Top() Uint256 {
	return max.Clone()
}

func (*Ring256) Bottom() Uint256 {
	return minUint256.Clone()
}

func (*Ring256) Min(x Uint256, ys ...Uint256) Uint256 {
	res := x
	for _, y := range ys {
		res = res.Min(y)
	}
	return res
}

func (*Ring256) Max(x Uint256, ys ...Uint256) Uint256 {
	res := x
	for _, y := range ys {
		res = res.Max(y)
	}
	return res
}

/*.--------------------------------------------------------------------------.*/
/*.------------------------------- Uint256 ----------------------------------.*/
/*.--------------------------------------------------------------------------.*/

func New(bot, lo, hi, top uint64) Uint256 {
	return Uint256{bot, lo, hi, top}
}

func NewFromBytes(b []byte) Uint256 {
	res, err := zero.SetBytesWide(b)
	if err != nil {
		panic(errs.WrapFailed(err, "this should never happen. SetBytesWide failed"))
	}
	return res
}

func (Uint256) Ring2k() *Ring256 {
	return Ring()
}

// === Basic Methods.

func (u Uint256) Equal(v Uint256) bool {
	eqBot := ct.Equal(u[0], v[0])
	eqLo := ct.Equal(u[1], v[1])
	eqHi := ct.Equal(u[2], v[2])
	eqTop := ct.Equal(u[3], v[3])
	return (eqBot & eqLo & eqHi & eqTop) == 1
}

func (u Uint256) Clone() Uint256 {
	return Uint256{u[0], u[1], u[2], u[3]}
}

func (u Uint256) MarshalJSON() ([]byte, error) {
	e := &pem.Block{
		Type:  u.Ring2k().Name(),
		Bytes: u.Bytes(),
	}
	marshalled, err := json.Marshal(e)
	if err != nil {
		return nil, errs.WrapFailed(err, "json marshal failed")
	}
	return marshalled, nil
}

// === Additive Groupoid Methods.

func (u Uint256) Add(rhs Uint256) Uint256 {
	var (
		carry uint64
		res   Uint256
	)
	res[0], carry = bits.Add64(u[0], rhs[0], 0)
	res[1], carry = bits.Add64(u[1], rhs[1], carry)
	res[2], carry = bits.Add64(u[2], rhs[2], carry)
	res[3] = u[3] + rhs[3] + carry
	return res
}

func (u Uint256) ApplyAdd(rhs Uint256, n *saferith.Nat) Uint256 {
	return u.Mul(u.SetNat(n))
}

func (u Uint256) Double() Uint256 {
	return u.Add(u)
}

func (u Uint256) Triple() Uint256 {
	return u.Mul(Uint256{3, 0, 0, 0})
}

// === Additive Monoid Methods.

func (u Uint256) IsAdditiveIdentity() bool {
	return u.IsZero()
}

// === Additive Group Methods.

func (u Uint256) AdditiveInverse() Uint256 {
	return Uint256{^u[0], ^u[1], ^u[2], ^u[3]}.Add(one)
}

func (u Uint256) IsAdditiveInverse(of Uint256) bool {
	return u.Add(of).IsZero()
}

func (u Uint256) Neg() Uint256 {
	return u.AdditiveInverse()
}

func (u Uint256) Sub(rhs Uint256) (res Uint256) {
	var borrow uint64
	res[0], borrow = bits.Sub64(u[0], rhs[0], 0)
	res[1], borrow = bits.Sub64(u[1], rhs[1], borrow)
	res[2], borrow = bits.Sub64(u[2], rhs[2], borrow)
	res[3] = u[3] - rhs[3] - borrow
	return res
}

func (u Uint256) ApplySub(rhs Uint256, n *saferith.Nat) Uint256 {
	return u.Sub(rhs.Mul(u.SetNat(n)))
}

// === Multiplicative Groupoid Methods.

func (u Uint256) Mul(rhs Uint256) (r Uint256) {
	var a1, a2, a3, carry uint64
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

func (u Uint256) ApplyMul(rhs Uint256, n *saferith.Nat) (res Uint256) {
	if n.EqZero() == 1 {
		return u
	}
	var (
		accumulator, sum Uint256
	)
	nBytes := n.Bytes()
	accumulator = ring256Instance.Select(bitstring.PackedBits(nBytes).Select(0) != 0, res, rhs)
	for i := len(nBytes)*8 - 2; i >= 0; i-- {
		accumulator = accumulator.Mul(rhs)
		sum = res.Add(accumulator)
		ring256Instance.Select(bitstring.PackedBits(nBytes).Select(i) != 0, res, sum)
	}
	return res.Mul(u)
}

func (u Uint256) Square() Uint256 {
	return u.Mul(u)
}

func (u Uint256) Cube() Uint256 {
	return u.Square().Mul(u)
}

// === Multiplicative Monoid Methods.

func (u Uint256) IsMultiplicativeIdentity() bool {
	return u.Equal(one)
}

// === Ring Methods.

func (u Uint256) MulAdd(p, q Uint256) Uint256 {
	return u.Mul(p).Add(q)
}

func (Uint256) Sqrt() (Uint256, error) {
	panic("not implemented")
}

func (u Uint256) Uint64() uint64 {
	return u[0]
}

// === NatLike Methods.

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

// === Theoretic Lattice Methods.

func (u Uint256) Cmp(v Uint256) algebra.Ordering {
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
func (u Uint256) Join(v Uint256) Uint256 {
	return u.Max(v)
}

func (u Uint256) Meet(v Uint256) Uint256 {
	return u.Min(v)
}

// === Integer Methods.

func (u Uint256) IsZero() bool {
	return ct.Equal(u[0]&u[1]&u[2]&u[3], 0) == 1
}

func (u Uint256) IsOne() bool {
	return (ct.Equal(u[1]&u[2]&u[3], 0) & ct.Equal(u[0], 1)) == 1
}

func (u Uint256) IsEven() bool {
	return u[0]&1 == 0
}

func (u Uint256) IsOdd() bool {
	return u[0]&1 == 1
}

func (Uint256) Increment() {
	panic("u not passed by reference")
}

func (Uint256) Decrement() {
	panic("u not passed by reference")
}

// === Bounded Theoretic Lattice Methods.

func (u Uint256) IsBottom() bool {
	return u.Equal(minUint256)
}

func (u Uint256) IsTop() bool {
	return u.Equal(max)
}

func (u Uint256) Min(rhs Uint256) Uint256 {
	return u.Ring2k().Select(u.Cmp(rhs) == algebra.LessThan, u, rhs)
}

func (u Uint256) Max(rhs Uint256) Uint256 {
	return u.Ring2k().Select(u.Cmp(rhs) == algebra.GreaterThan, u, rhs)
}

// === BytesLike Methods.

func (u Uint256) Bytes() []byte {
	b := make([]byte, RingBytes)
	binary.BigEndian.PutUint64(b[:8], u[3])
	binary.BigEndian.PutUint64(b[8:16], u[2])
	binary.BigEndian.PutUint64(b[16:24], u[1])
	binary.BigEndian.PutUint64(b[24:], u[0])
	return b
}

func (Uint256) SetBytes(src []byte) (dst Uint256, err error) {
	if len(src) != RingBytes {
		return Uint256{}, errs.NewLength("length of bytes is %d, should be %d",
			len(src), RingBytes)
	}
	dst[3] = binary.BigEndian.Uint64(src[:8])
	dst[2] = binary.BigEndian.Uint64(src[8:16])
	dst[1] = binary.BigEndian.Uint64(src[16:24])
	dst[0] = binary.BigEndian.Uint64(src[24:32])
	return dst, nil
}

func (Uint256) SetBytesWide(bigEndianBytes []byte) (dst Uint256, err error) {
	L := len(bigEndianBytes)
	if L > RingBytes {
		bigEndianBytes = bigEndianBytes[L-RingBytes:]
	} else if L < RingBytes {
		bigEndianBytes = bitstring.PadToLeft(bigEndianBytes, RingBytes-L)
	}
	dst[3] = binary.BigEndian.Uint64(bigEndianBytes[:8])
	dst[2] = binary.BigEndian.Uint64(bigEndianBytes[8:16])
	dst[1] = binary.BigEndian.Uint64(bigEndianBytes[16:24])
	dst[0] = binary.BigEndian.Uint64(bigEndianBytes[24:32])
	return dst, nil
}

// And returns u&v.
func (u Uint256) And(v Uint256) Uint256 {
	return Uint256{
		u[0] & v[0],
		u[1] & v[1],
		u[2] & v[2],
		u[3] & v[3],
	}
}

// Or returns u|v.
func (u Uint256) Or(v Uint256) Uint256 {
	return Uint256{
		u[0] | v[0],
		u[1] | v[1],
		u[2] | v[2],
		u[3] | v[3],
	}
}

// Xor returns u^v.
func (u Uint256) Xor(v Uint256) Uint256 {
	return Uint256{
		u[0] ^ v[0],
		u[1] ^ v[1],
		u[2] ^ v[2],
		u[3] ^ v[3],
	}
}

// AddUint64 returns u+v with wraparound semantics; for example,
// Max.AddUint64(1) == Zero.
func (u Uint256) AddUint64(v uint64) (res Uint256) {
	var carry uint64
	res[0], carry = bits.Add64(u[0], v, 0)
	res[1], carry = bits.Add64(u[1], 0, carry)
	res[2], carry = bits.Add64(u[2], 0, carry)
	res[3], _ = bits.Add64(u[3], 0, carry)
	return res
}

// SubUint64 returns u-v with wraparound semantics; for example,
// Zero.SubUint64(1) == Max.
func (u Uint256) SubUint64(v uint64) (res Uint256) {
	var borrow uint64
	res[0], borrow = bits.Sub64(u[0], v, 0)
	res[1], borrow = bits.Sub64(u[1], 0, borrow)
	res[2], borrow = bits.Sub64(u[2], 0, borrow)
	res[3], _ = bits.Sub64(u[3], 0, borrow)
	return res
}

// Lsh returns u<<n.
func (u Uint256) Lsh(n uint) (s Uint256) {
	s = Uint256{}
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

// Rsh returns u>>n.
func (u Uint256) Rsh(n uint) (s Uint256) {
	s = Uint256{}
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

// String returns the hexadecimal encoding of u.
func (u Uint256) String() string {
	return "0x" + u.Nat().String()
}

// LeadingZeros returns the number of leading zero bits in u.
func (u Uint256) LeadingZeros() int {
	maskLt2_192 := uint64(ct.Equal(u[3], 0)) - uint64(1)
	maskLt2_128 := uint64(ct.Equal(u[2], 0)) - uint64(1)
	maskLt2_64 := uint64(ct.Equal(u[1], 0)) - uint64(1)
	return int(uint64(bits.LeadingZeros64(u[3])) +
		uint64(bits.LeadingZeros64(u[2])+64)&maskLt2_192 +
		uint64(bits.LeadingZeros64(u[1])+128)&maskLt2_128 +
		uint64(bits.LeadingZeros64(u[0])+192)&maskLt2_64)
}

// NewFromBig converts i to a Uint256 value. It panics if i is negative or
// overflows 128 bits.
func NewFromBig(i *big.Int) (u Uint256) {
	if i.Sign() < 0 {
		panic("value cannot be negative")
	}
	u[0] = i.Uint64()
	u[1] = i.Rsh(i, 64).Uint64()
	u[2] = i.Rsh(i, 128).Uint64()
	u[3] = i.Rsh(i, 192).Uint64()
	return u
}
