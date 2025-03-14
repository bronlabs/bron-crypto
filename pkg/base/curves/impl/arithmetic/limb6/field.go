package limb6

import (
	"math/big"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/bitstring"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

// FieldLimbs is the number of limbs needed to represent this field.
const FieldLimbs = 6

// FieldBytes is the number of bytes needed to represent this field.
const FieldBytes = 48

// WideFieldBytes is the number of bytes needed for safe conversion
// to this field to avoid bias when reduced.
const WideFieldBytes = 96

// FieldValue represents a field element.
type FieldValue struct {
	// Value is the field elements value
	Value [FieldLimbs]uint64
	// Params are the field parameters
	Params *FieldParams
	// Arithmetic are the field methods
	Arithmetic FieldArithmetic

	_ ds.Incomparable
}

// FieldParams are the field parameters.
type FieldParams struct {
	// R is 2^256 mod Modulus
	R [FieldLimbs]uint64
	// R2 is 2^512 mod Modulus
	R2 [FieldLimbs]uint64
	// R3 is 2^768 mod Modulus
	R3 [FieldLimbs]uint64
	// ModulusLimbs of the field
	ModulusLimbs [FieldLimbs]uint64
	// Modulus as big.Int
	Modulus *saferith.Modulus

	_ ds.Incomparable
}

// FieldArithmetic are the methods that can be done on a field.
type FieldArithmetic interface {
	// ToMontgomery converts this field to montgomery form
	ToMontgomery(out, arg *[FieldLimbs]uint64)
	// FromMontgomery converts this field from montgomery form
	FromMontgomery(out, arg *[FieldLimbs]uint64)
	// Neg performs modular negation
	Neg(out, arg *[FieldLimbs]uint64)
	// Square performs modular square
	Square(out, arg *[FieldLimbs]uint64)
	// Mul performs modular multiplication
	Mul(out, arg1, arg2 *[FieldLimbs]uint64)
	// Add performs modular addition
	Add(out, arg1, arg2 *[FieldLimbs]uint64)
	// Sub performs modular subtraction
	Sub(out, arg1, arg2 *[FieldLimbs]uint64)
	// Sqrt performs modular square root
	Sqrt(wasSquare *uint64, out, arg *[FieldLimbs]uint64)
	// Invert performs modular inverse
	Invert(wasInverted *uint64, out, arg *[FieldLimbs]uint64)
	// FromBytes converts a little endian byte array into a field element
	FromBytes(out *[FieldLimbs]uint64, arg *[FieldBytes]byte)
	// ToBytes converts a field element to a little endian byte array
	ToBytes(out *[FieldBytes]byte, arg *[FieldLimbs]uint64)
	// Selectznz performs conditional select.
	// selects arg1 if choice == 0 and arg2 if choice == 1
	Selectznz(out, arg1, arg2 *[FieldLimbs]uint64, choice uint64)
	// Nonzero returns 0 if arg == 0, 1 otherwise
	Nonzero(wasNonZero *uint64, arg *[FieldLimbs]uint64)
	// SetOne sets arg := 1
	SetOne(out *[FieldLimbs]uint64)
}

// Cmp returns -1 if f < rhs
// 0 if f == rhs
// 1 if f > rhs.
func (f *FieldValue) Cmp(rhs *FieldValue) int64 {
	var l, r [FieldLimbs]uint64
	f.Arithmetic.FromMontgomery(&l, &f.Value)
	f.Arithmetic.FromMontgomery(&r, &rhs.Value)
	return ct.SliceCmpLE(l[:], r[:])
}

// Equal returns 1 if f == rhs, 0 otherwise.
func (f *FieldValue) Equal(rhs *FieldValue) uint64 {
	return ct.SliceEqual(f.Value[:], rhs.Value[:])
}

// New returns a brand-new field.
func (f *FieldValue) New() *FieldValue {
	return &FieldValue{
		Value:      [FieldLimbs]uint64{0, 0, 0, 0, 0, 0},
		Params:     f.Params,
		Arithmetic: f.Arithmetic,
	}
}

// IsZero returns 1 if f == 0, 0 otherwise.
func (f *FieldValue) IsZero() uint64 {
	t := uint64(0)
	f.Arithmetic.Nonzero(&t, &f.Value)
	return ((t | -t) >> 63) ^ 1
}

// IsNonZero returns 1 if f != 0, 0 otherwise.
func (f *FieldValue) IsNonZero() uint64 {
	t := uint64(0)
	f.Arithmetic.Nonzero(&t, &f.Value)
	return (t | -t) >> 63
}

// IsOne returns 1 if f == 1, 0 otherwise.
func (f *FieldValue) IsOne() uint64 {
	var one [FieldLimbs]uint64
	f.Arithmetic.SetOne(&one)
	return ct.SliceEqual(f.Value[:], one[:])
}

// Set f = rhs.
func (f *FieldValue) Set(rhs *FieldValue) *FieldValue {
	f.Value = rhs.Value
	f.Params = rhs.Params
	f.Arithmetic = rhs.Arithmetic
	return f
}

// SetUint64 f = rhs.
func (f *FieldValue) SetUint64(rhs uint64) *FieldValue {
	t := &[FieldLimbs]uint64{rhs, 0, 0, 0, 0, 0}
	f.Arithmetic.ToMontgomery(&f.Value, t)
	return f
}

// SetOne f = r.
func (f *FieldValue) SetOne() *FieldValue {
	f.Arithmetic.SetOne(&f.Value)
	return f
}

// SetZero f = 0.
func (f *FieldValue) SetZero() *FieldValue {
	f.Value = [FieldLimbs]uint64{}
	return f
}

// SetBytesWide takes 96 bytes as input and treats them as a 512-bit number.
// Attributed to https://github.com/zcash/pasta_curves/blob/main/src/fields/Fp.rs#L255
// We reduce an arbitrary 512-bit number by decomposing it into two 256-bit digits
// with the higher bits multiplied by 2^256. Thus, we perform two reductions
//
// 1. the lower bits are multiplied by r^2, as normal
// 2. the upper bits are multiplied by r^2 * 2^256 = r^3
//
// and computing their sum in the field. It remains to see that arbitrary 256-bit
// numbers can be placed into Montgomery form safely using the reduction. The
// reduction works so long as the product is less than r=2^256 multiplied by
// the modulus. This holds because for any `c` smaller than the modulus, we have
// that (2^256 - 1)*c is an acceptable product for the reduction. Therefore, the
// reduction always works so long as `c` is in the field; in this case it is either the
// constant `r2` or `r3`.
func (f *FieldValue) SetBytesWide(input *[WideFieldBytes]byte) *FieldValue {
	var d0, d1 [FieldLimbs]uint64
	f.Arithmetic.FromBytes(&d0, (*[FieldBytes]byte)(input[:FieldBytes]))
	f.Arithmetic.FromBytes(&d1, (*[FieldBytes]byte)(input[FieldBytes:]))

	// d0*r2 + d1*r3
	f.Arithmetic.Mul(&d0, &d0, &f.Params.R2)
	f.Arithmetic.Mul(&d1, &d1, &f.Params.R3)
	f.Arithmetic.Add(&f.Value, &d0, &d1)
	return f
}

// SetBytes attempts to convert a little endian byte representation
// of a scalar into a `Fp`, failing if input is not canonical.
func (f *FieldValue) SetBytes(input *[FieldBytes]byte) (*FieldValue, error) {
	d0 := [FieldLimbs]uint64{0, 0, 0, 0, 0, 0}
	f.Arithmetic.FromBytes(&d0, input)

	if ct.SliceCmpLE(d0[:], f.Params.ModulusLimbs[:]) != -1 {
		return nil, errs.NewFailed("invalid byte sequence")
	}
	return f.SetLimbs(&d0), nil
}

// SetNat initialises an element from saferith.Nat
// The value is reduced by the modulus.
func (f *FieldValue) SetNat(nat *saferith.Nat) *FieldValue {
	var buffer [FieldBytes]byte
	t := new(saferith.Nat).Mod(nat, f.Params.Modulus)
	t.FillBytes(buffer[:])
	copy(buffer[:], bitstring.ReverseBytes(buffer[:]))
	_, _ = f.SetBytes(&buffer)
	return f
}

// SetBigInt initialises an element from big.Int
// The value is reduced by the modulus.
func (f *FieldValue) SetBigInt(bi *big.Int) *FieldValue {
	var buffer [FieldBytes]byte
	t := new(big.Int).Set(bi)
	t.Mod(t, f.Params.Modulus.Big())
	t.FillBytes(buffer[:])
	copy(buffer[:], bitstring.ReverseBytes(buffer[:]))
	_, _ = f.SetBytes(&buffer)
	return f
}

// SetRaw converts a raw array into a field element
// Assumes input is already in montgomery form.
func (f *FieldValue) SetRaw(input *[FieldLimbs]uint64) *FieldValue {
	f.Value = *input
	return f
}

// SetLimbs converts an array into a field element
// by converting to montgomery form.
func (f *FieldValue) SetLimbs(input *[FieldLimbs]uint64) *FieldValue {
	f.Arithmetic.ToMontgomery(&f.Value, input)
	return f
}

// Bytes converts this element into a byte representation
// in little endian byte order.
func (f *FieldValue) Bytes() [FieldBytes]byte {
	var output [FieldBytes]byte
	tv := &[FieldLimbs]uint64{}
	f.Arithmetic.FromMontgomery(tv, &f.Value)
	f.Arithmetic.ToBytes(&output, tv)
	return output
}

// Nat converts this element into the big.Int struct.
func (f *FieldValue) Nat() *saferith.Nat {
	buffer := f.Bytes()
	return new(saferith.Nat).SetBytes(bitstring.ReverseBytes(buffer[:]))
}

// BigInt converts this element into the big.Int struct.
func (f *FieldValue) BigInt() *big.Int {
	buffer := f.Bytes()
	return new(big.Int).SetBytes(bitstring.ReverseBytes(buffer[:]))
}

// Raw converts this element into the a [Field4Limbs]uint64.
func (f *FieldValue) Raw() [FieldLimbs]uint64 {
	res := &[FieldLimbs]uint64{}
	f.Arithmetic.FromMontgomery(res, &f.Value)
	return *res
}

// Double this element.
func (f *FieldValue) Double(a *FieldValue) *FieldValue {
	f.Arithmetic.Add(&f.Value, &a.Value, &a.Value)
	return f
}

// Square this element.
func (f *FieldValue) Square(a *FieldValue) *FieldValue {
	f.Arithmetic.Square(&f.Value, &a.Value)
	return f
}

func (f *FieldValue) MulBy3b(arg *FieldValue) *FieldValue {
	a := new(FieldValue)
	t := new(FieldValue)

	a.Set(arg)
	t.Set(arg)
	a.Double(arg)
	t.Double(a)
	a.Double(t)
	a.Add(a, t)
	return f.Set(a)
}

// Sqrt this element, if it exists. If true, then value
// is a square root. If false, value is a QNR.
func (f *FieldValue) Sqrt(a *FieldValue) (*FieldValue, bool) {
	wasSquare := uint64(0)
	f.Arithmetic.Sqrt(&wasSquare, &f.Value, &a.Value)
	return f, wasSquare == 1
}

// Invert this element i.e. compute the multiplicative inverse
// return false, zero if this element is zero.
func (f *FieldValue) Invert(a *FieldValue) (*FieldValue, bool) {
	wasInverted := uint64(0)
	f.Arithmetic.Invert(&wasInverted, &f.Value, &a.Value)
	return f, wasInverted == 1
}

// Mul returns the result from multiplying this element by rhs.
func (f *FieldValue) Mul(lhs, rhs *FieldValue) *FieldValue {
	f.Arithmetic.Mul(&f.Value, &lhs.Value, &rhs.Value)
	return f
}

// Sub returns the result from subtracting rhs from this element.
func (f *FieldValue) Sub(lhs, rhs *FieldValue) *FieldValue {
	f.Arithmetic.Sub(&f.Value, &lhs.Value, &rhs.Value)
	return f
}

// Add returns the result from adding rhs to this element.
func (f *FieldValue) Add(lhs, rhs *FieldValue) *FieldValue {
	f.Arithmetic.Add(&f.Value, &lhs.Value, &rhs.Value)
	return f
}

// Neg returns negation of this element.
func (f *FieldValue) Neg(input *FieldValue) *FieldValue {
	f.Arithmetic.Neg(&f.Value, &input.Value)
	return f
}

// Exp raises base^exp.
func (f *FieldValue) Exp(base, exp *FieldValue) *FieldValue {
	e := [FieldLimbs]uint64{}
	f.Arithmetic.FromMontgomery(&e, &exp.Value)
	Pow(&f.Value, &base.Value, &e, f.Params, f.Arithmetic)
	return f
}

// CMove sets f = lhs if choice == 0 and f = rhs if choice == 1.
func (f *FieldValue) CMove(lhs, rhs *FieldValue, choice uint64) *FieldValue {
	f.Arithmetic.Selectznz(&f.Value, &lhs.Value, &rhs.Value, choice)
	return f
}

// Pow raises base^exp. The result is written to out.
// Public only for convenience for some internal implementations.
func Pow(out, base, exp *[FieldLimbs]uint64, params *FieldParams, arithmetic FieldArithmetic) {
	res := [FieldLimbs]uint64{}
	tmp := [FieldLimbs]uint64{}

	arithmetic.SetOne(&res)
	for i := len(exp) - 1; i >= 0; i-- {
		for j := 63; j >= 0; j-- {
			arithmetic.Square(&res, &res)
			arithmetic.Mul(&tmp, &res, base)
			arithmetic.Selectznz(&res, &res, &tmp, (exp[i]>>j)&1)
		}
	}
	*out = res
}
