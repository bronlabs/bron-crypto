package bls12381impl

import (
	"encoding/binary"
	"io"
	"strings"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

// Fp field element mod p.
type Fp [Limbs]uint64

var (
	FpModulusLimbs = Fp{
		0xb9feffffffffaaab,
		0x1eabfffeb153ffff,
		0x6730d2a0f6b0f624,
		0x64774b84f38512bf,
		0x4b1ba7b6434bacd7,
		0x1a0111ea397fe69a,
	}
	HalfModulus = Fp{
		0xdcff_7fff_ffff_d556,
		0x0f55_ffff_58a9_ffff,
		0xb398_6950_7b58_7b12,
		0xb23b_a5c2_79c2_895f,
		0x258d_d3db_21a5_d66b,
		0x0d00_88f5_1cbf_f34d,
	}
	// 2^256 mod p.
	R = Fp{
		0x760900000002fffd,
		0xebf4000bc40c0002,
		0x5f48985753c758ba,
		0x77ce585370525745,
		0x5c071a97a256ec6d,
		0x15f65ec3fa80e493,
	}
	// 2^512 mod p.
	R2 = Fp{
		0xf4df1f341c341746,
		0x0a76e6a609d104f1,
		0x8de5476c4c95b6d5,
		0x67eb88a9939d83c0,
		0x9a793e85b519952d,
		0x11988fe592cae3aa,
	}
	// 2^768 mod p.
	R3 = Fp{
		0xed48ac6bd94ca1e0,
		0x315f831e03a7adf8,
		0x9a53352a615e29dd,
		0x34c04e5e921e1761,
		0x2512d43565724728,
		0x0aa6346091755d4d,
	}
	FpModulus, _ = saferith.ModulusFromHex(strings.ToUpper("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab"))
)

// inv = -(p^{-1} mod 2^64) mod 2^64.
const (
	inv       = 0x89f3_fffc_fffc_fffd
	hashBytes = 64
)

// IsZero returns 1 if fp == 0, 0 otherwise.
func (f *Fp) IsZero() int {
	t := f[0]
	t |= f[1]
	t |= f[2]
	t |= f[3]
	t |= f[4]
	t |= f[5]
	return int(((int64(t) | int64(-t)) >> 63) + 1)
}

// IsNonZero returns 1 if fp != 0, 0 otherwise.
func (f *Fp) IsNonZero() int {
	t := f[0]
	t |= f[1]
	t |= f[2]
	t |= f[3]
	t |= f[4]
	t |= f[5]
	return int(-((int64(t) | int64(-t)) >> 63))
}

// IsOne returns 1 if fp == 1, 0 otherwise.
func (f *Fp) IsOne() int {
	return f.Equal(&R)
}

// Cmp returns -1 if f < rhs
// 0 if f == rhs
// 1 if f > rhs.
func (f *Fp) Cmp(rhs *Fp) int {
	gt := uint64(0)
	lt := uint64(0)
	for i := 5; i >= 0; i-- {
		// convert to two 64-bit numbers where
		// the leading bits are zeros and hold no meaning
		//  so rhs - f actually means gt
		// and f - rhs actually means lt.
		rhsH := rhs[i] >> 32
		rhsL := rhs[i] & 0xffffffff
		lhsH := f[i] >> 32
		lhsL := f[i] & 0xffffffff

		// Check the leading bit
		// if negative then f > rhs
		// if positive then f < rhs
		gt |= (rhsH - lhsH) >> 32 & 1 &^ lt
		lt |= (lhsH - rhsH) >> 32 & 1 &^ gt
		gt |= (rhsL - lhsL) >> 32 & 1 &^ lt
		lt |= (lhsL - rhsL) >> 32 & 1 &^ gt
	}
	// Make the result -1 for <, 0 for =, 1 for >
	return int(gt) - int(lt)
}

// Equal returns 1 if fp == rhs, 0 otherwise.
func (f *Fp) Equal(rhs *Fp) int {
	t := f[0] ^ rhs[0]
	t |= f[1] ^ rhs[1]
	t |= f[2] ^ rhs[2]
	t |= f[3] ^ rhs[3]
	t |= f[4] ^ rhs[4]
	t |= f[5] ^ rhs[5]
	return int(((int64(t) | int64(-t)) >> 63) + 1)
}

// LexicographicallyLargest returns 1 if
// this element is strictly lexicographically larger than its negation
// 0 otherwise.
func (f *Fp) LexicographicallyLargest() int {
	var ff Fp
	ff.fromMontgomery(f)

	_, borrow := sbb(ff[0], HalfModulus[0], 0)
	_, borrow = sbb(ff[1], HalfModulus[1], borrow)
	_, borrow = sbb(ff[2], HalfModulus[2], borrow)
	_, borrow = sbb(ff[3], HalfModulus[3], borrow)
	_, borrow = sbb(ff[4], HalfModulus[4], borrow)
	_, borrow = sbb(ff[5], HalfModulus[5], borrow)

	return (int(borrow) - 1) & 1
}

// Sgn0 returns the lowest bit value.
func (f *Fp) Sgn0() int {
	t := new(Fp).fromMontgomery(f)
	return int(t[0] & 1)
}

// SetOne fp = r.
func (f *Fp) SetOne() *Fp {
	f[0] = R[0]
	f[1] = R[1]
	f[2] = R[2]
	f[3] = R[3]
	f[4] = R[4]
	f[5] = R[5]
	return f
}

// SetZero fp = 0.
func (f *Fp) SetZero() *Fp {
	f[0] = 0
	f[1] = 0
	f[2] = 0
	f[3] = 0
	f[4] = 0
	f[5] = 0
	return f
}

// SetUint64 fp = rhs.
func (f *Fp) SetUint64(rhs uint64) *Fp {
	f[0] = rhs
	f[1] = 0
	f[2] = 0
	f[3] = 0
	f[4] = 0
	f[5] = 0
	return f.toMontgomery(f)
}

// Random generates a random field element.
func (f *Fp) Random(prng io.Reader) (*Fp, error) {
	var t [WideFieldBytes]byte
	_, err := io.ReadFull(prng, t[:])
	if err != nil {
		return nil, errs.WrapRandomSample(err, "reader failed")
	}
	return f.SetBytesWide(&t), nil
}

// toMontgomery converts this field to montgomery form.
func (f *Fp) toMontgomery(a *Fp) *Fp {
	// arg.R^0 * R^2 / R = arg.R
	return f.Mul(a, &R2)
}

// fromMontgomery converts this field from montgomery form.
func (f *Fp) fromMontgomery(a *Fp) *Fp {
	// Mul by 1 is division by 2^256 mod q
	// out.Mul(arg, &[impl.FieldLimbs]uint64{1, 0, 0, 0})
	return f.montReduce(&[Limbs * 2]uint64{a[0], a[1], a[2], a[3], a[4], a[5], 0, 0, 0, 0, 0, 0})
}

// Neg performs modular negation.
func (f *Fp) Neg(a *Fp) *Fp {
	// Subtract `arg` from `modulus`. Ignore final borrow
	// since it can't underflow.
	var t [Limbs]uint64
	var borrow uint64
	t[0], borrow = sbb(FpModulusLimbs[0], a[0], 0)
	t[1], borrow = sbb(FpModulusLimbs[1], a[1], borrow)
	t[2], borrow = sbb(FpModulusLimbs[2], a[2], borrow)
	t[3], borrow = sbb(FpModulusLimbs[3], a[3], borrow)
	t[4], borrow = sbb(FpModulusLimbs[4], a[4], borrow)
	t[5], _ = sbb(FpModulusLimbs[5], a[5], borrow)

	// t could be `modulus` if `arg`=0. Set mask=0 if self=0
	// and 0xff..ff if `arg`!=0
	mask := a[0] | a[1] | a[2] | a[3] | a[4] | a[5]
	mask = -((mask | -mask) >> 63)
	f[0] = t[0] & mask
	f[1] = t[1] & mask
	f[2] = t[2] & mask
	f[3] = t[3] & mask
	f[4] = t[4] & mask
	f[5] = t[5] & mask
	return f
}

// Square performs modular square.
func (f *Fp) Square(a *Fp) *Fp {
	var r [2 * Limbs]uint64
	var carry uint64

	r[1], carry = mac(0, a[0], a[1], 0)
	r[2], carry = mac(0, a[0], a[2], carry)
	r[3], carry = mac(0, a[0], a[3], carry)
	r[4], carry = mac(0, a[0], a[4], carry)
	r[5], r[6] = mac(0, a[0], a[5], carry)

	r[3], carry = mac(r[3], a[1], a[2], 0)
	r[4], carry = mac(r[4], a[1], a[3], carry)
	r[5], carry = mac(r[5], a[1], a[4], carry)
	r[6], r[7] = mac(r[6], a[1], a[5], carry)

	r[5], carry = mac(r[5], a[2], a[3], 0)
	r[6], carry = mac(r[6], a[2], a[4], carry)
	r[7], r[8] = mac(r[7], a[2], a[5], carry)

	r[7], carry = mac(r[7], a[3], a[4], 0)
	r[8], r[9] = mac(r[8], a[3], a[5], carry)

	r[9], r[10] = mac(r[9], a[4], a[5], 0)

	r[11] = r[10] >> 63
	r[10] = (r[10] << 1) | r[9]>>63
	r[9] = (r[9] << 1) | r[8]>>63
	r[8] = (r[8] << 1) | r[7]>>63
	r[7] = (r[7] << 1) | r[6]>>63
	r[6] = (r[6] << 1) | r[5]>>63
	r[5] = (r[5] << 1) | r[4]>>63
	r[4] = (r[4] << 1) | r[3]>>63
	r[3] = (r[3] << 1) | r[2]>>63
	r[2] = (r[2] << 1) | r[1]>>63
	r[1] <<= 1

	r[0], carry = mac(0, a[0], a[0], 0)
	r[1], carry = adc(0, r[1], carry)
	r[2], carry = mac(r[2], a[1], a[1], carry)
	r[3], carry = adc(0, r[3], carry)
	r[4], carry = mac(r[4], a[2], a[2], carry)
	r[5], carry = adc(0, r[5], carry)
	r[6], carry = mac(r[6], a[3], a[3], carry)
	r[7], carry = adc(0, r[7], carry)
	r[8], carry = mac(r[8], a[4], a[4], carry)
	r[9], carry = adc(0, r[9], carry)
	r[10], carry = mac(r[10], a[5], a[5], carry)
	r[11], _ = adc(0, r[11], carry)

	return f.montReduce(&r)
}

// Double this element.
func (f *Fp) Double(a *Fp) *Fp {
	return f.Add(a, a)
}

// Mul performs modular multiplication.
func (f *Fp) Mul(arg1, arg2 *Fp) *Fp {
	// Schoolbook multiplication
	var r [2 * Limbs]uint64
	var carry uint64

	r[0], carry = mac(0, arg1[0], arg2[0], 0)
	r[1], carry = mac(0, arg1[0], arg2[1], carry)
	r[2], carry = mac(0, arg1[0], arg2[2], carry)
	r[3], carry = mac(0, arg1[0], arg2[3], carry)
	r[4], carry = mac(0, arg1[0], arg2[4], carry)
	r[5], r[6] = mac(0, arg1[0], arg2[5], carry)

	r[1], carry = mac(r[1], arg1[1], arg2[0], 0)
	r[2], carry = mac(r[2], arg1[1], arg2[1], carry)
	r[3], carry = mac(r[3], arg1[1], arg2[2], carry)
	r[4], carry = mac(r[4], arg1[1], arg2[3], carry)
	r[5], carry = mac(r[5], arg1[1], arg2[4], carry)
	r[6], r[7] = mac(r[6], arg1[1], arg2[5], carry)

	r[2], carry = mac(r[2], arg1[2], arg2[0], 0)
	r[3], carry = mac(r[3], arg1[2], arg2[1], carry)
	r[4], carry = mac(r[4], arg1[2], arg2[2], carry)
	r[5], carry = mac(r[5], arg1[2], arg2[3], carry)
	r[6], carry = mac(r[6], arg1[2], arg2[4], carry)
	r[7], r[8] = mac(r[7], arg1[2], arg2[5], carry)

	r[3], carry = mac(r[3], arg1[3], arg2[0], 0)
	r[4], carry = mac(r[4], arg1[3], arg2[1], carry)
	r[5], carry = mac(r[5], arg1[3], arg2[2], carry)
	r[6], carry = mac(r[6], arg1[3], arg2[3], carry)
	r[7], carry = mac(r[7], arg1[3], arg2[4], carry)
	r[8], r[9] = mac(r[8], arg1[3], arg2[5], carry)

	r[4], carry = mac(r[4], arg1[4], arg2[0], 0)
	r[5], carry = mac(r[5], arg1[4], arg2[1], carry)
	r[6], carry = mac(r[6], arg1[4], arg2[2], carry)
	r[7], carry = mac(r[7], arg1[4], arg2[3], carry)
	r[8], carry = mac(r[8], arg1[4], arg2[4], carry)
	r[9], r[10] = mac(r[9], arg1[4], arg2[5], carry)

	r[5], carry = mac(r[5], arg1[5], arg2[0], 0)
	r[6], carry = mac(r[6], arg1[5], arg2[1], carry)
	r[7], carry = mac(r[7], arg1[5], arg2[2], carry)
	r[8], carry = mac(r[8], arg1[5], arg2[3], carry)
	r[9], carry = mac(r[9], arg1[5], arg2[4], carry)
	r[10], r[11] = mac(r[10], arg1[5], arg2[5], carry)

	return f.montReduce(&r)
}

// MulBy3b returns arg * 12 or 3 * b.
func (f *Fp) MulBy3b(arg *Fp) *Fp {
	var a, t Fp
	a.Double(arg) // 2
	t.Double(&a)  // 4
	a.Double(&t)  // 8
	a.Add(&a, &t) // 12
	return f.Set(&a)
}

// Add performs modular addition.
func (f *Fp) Add(arg1, arg2 *Fp) *Fp {
	var t Fp
	var carry uint64

	t[0], carry = adc(arg1[0], arg2[0], 0)
	t[1], carry = adc(arg1[1], arg2[1], carry)
	t[2], carry = adc(arg1[2], arg2[2], carry)
	t[3], carry = adc(arg1[3], arg2[3], carry)
	t[4], carry = adc(arg1[4], arg2[4], carry)
	t[5], _ = adc(arg1[5], arg2[5], carry)

	// Subtract the modulus to ensure the value
	// is smaller.
	return f.Sub(&t, &FpModulusLimbs)
}

// Sub performs modular subtraction.
func (f *Fp) Sub(arg1, arg2 *Fp) *Fp {
	d0, borrow := sbb(arg1[0], arg2[0], 0)
	d1, borrow := sbb(arg1[1], arg2[1], borrow)
	d2, borrow := sbb(arg1[2], arg2[2], borrow)
	d3, borrow := sbb(arg1[3], arg2[3], borrow)
	d4, borrow := sbb(arg1[4], arg2[4], borrow)
	d5, borrow := sbb(arg1[5], arg2[5], borrow)

	// If underflow occurred on the final limb, borrow 0xff...ff, otherwise
	// borrow = 0x00...00. Conditionally mask to add the modulus
	borrow = -borrow
	d0, carry := adc(d0, FpModulusLimbs[0]&borrow, 0)
	d1, carry = adc(d1, FpModulusLimbs[1]&borrow, carry)
	d2, carry = adc(d2, FpModulusLimbs[2]&borrow, carry)
	d3, carry = adc(d3, FpModulusLimbs[3]&borrow, carry)
	d4, carry = adc(d4, FpModulusLimbs[4]&borrow, carry)
	d5, _ = adc(d5, FpModulusLimbs[5]&borrow, carry)

	f[0] = d0
	f[1] = d1
	f[2] = d2
	f[3] = d3
	f[4] = d4
	f[5] = d5
	return f
}

// Sqrt performs modular square root.
func (f *Fp) Sqrt(a *Fp) (fRes *Fp, wasSquare int) {
	// Shank's method, as p = 3 (mod 4). This means
	// exponentiate by (p+1)/4. This only works for elements
	// that are actually quadratic residue,
	// so check the result at the end.
	var c, z Fp
	z.pow(a, &Fp{
		0xee7fbfffffffeaab,
		0x07aaffffac54ffff,
		0xd9cc34a83dac3d89,
		0xd91dd2e13ce144af,
		0x92c6e9ed90d2eb35,
		0x0680447a8e5ff9a6,
	})

	c.Square(&z)
	wasSquare = c.Equal(a)
	f.CMove(f, &z, wasSquare)
	return f, wasSquare
}

// Invert performs modular inverse.
func (f *Fp) Invert(a *Fp) (fRes *Fp, wasInverted int) {
	// Exponentiate by p - 2
	t := &Fp{}
	t.pow(a, &Fp{
		0xb9feffffffffaaa9,
		0x1eabfffeb153ffff,
		0x6730d2a0f6b0f624,
		0x64774b84f38512bf,
		0x4b1ba7b6434bacd7,
		0x1a0111ea397fe69a,
	})
	wasInverted = a.IsNonZero()
	f.CMove(a, t, wasInverted)
	return f, wasInverted
}

// SetBytes converts a little endian byte array into a field element
// return 0 if the bytes are not in the field, 1 if they are.
func (f *Fp) SetBytes(arg *[FieldBytes]byte) (fRes *Fp, mask int) {
	var borrow uint64
	t := &Fp{}

	t[0] = binary.LittleEndian.Uint64(arg[:8])
	t[1] = binary.LittleEndian.Uint64(arg[8:16])
	t[2] = binary.LittleEndian.Uint64(arg[16:24])
	t[3] = binary.LittleEndian.Uint64(arg[24:32])
	t[4] = binary.LittleEndian.Uint64(arg[32:40])
	t[5] = binary.LittleEndian.Uint64(arg[40:])

	// Try to subtract the modulus
	_, borrow = sbb(t[0], FpModulusLimbs[0], 0)
	_, borrow = sbb(t[1], FpModulusLimbs[1], borrow)
	_, borrow = sbb(t[2], FpModulusLimbs[2], borrow)
	_, borrow = sbb(t[3], FpModulusLimbs[3], borrow)
	_, borrow = sbb(t[4], FpModulusLimbs[4], borrow)
	_, borrow = sbb(t[5], FpModulusLimbs[5], borrow)

	// If the element is smaller than modulus then the
	// subtraction will underflow, producing a borrow value
	// of 1. Otherwise, it'll be zero.
	mask = int(borrow)
	return f.CMove(f, t.toMontgomery(t), mask), mask
}

// SetBytesWide takes 96 bytes as input and treats them as a 512-bit number.
// Attributed to https://github.com/zcash/pasta_curves/blob/main/src/fields/Fp.rs#L255
// We reduce an arbitrary 768-bit number by decomposing it into two 384-bit digits
// with the higher bits multiplied by 2^384. Thus, we perform two reductions
//
// 1. the lower bits are multiplied by r^2, as normal
// 2. the upper bits are multiplied by r^2 * 2^384 = r^3
//
// and computing their sum in the field. It remains to see that arbitrary 384-bit
// numbers can be placed into Montgomery form safely using the reduction. The
// reduction works so long as the product is less than r=2^384 multiplied by
// the modulus. This holds because for any `c` smaller than the modulus, we have
// that (2^384 - 1)*c is an acceptable product for the reduction. Therefore, the
// reduction always works so long as `c` is in the field; in this case it is either the
// constant `r2` or `r3`.
func (f *Fp) SetBytesWide(a *[WideFieldBytes]byte) *Fp {
	d0 := &Fp{
		binary.LittleEndian.Uint64(a[:8]),
		binary.LittleEndian.Uint64(a[8:16]),
		binary.LittleEndian.Uint64(a[16:24]),
		binary.LittleEndian.Uint64(a[24:32]),
		binary.LittleEndian.Uint64(a[32:40]),
		binary.LittleEndian.Uint64(a[40:48]),
	}
	d1 := &Fp{
		binary.LittleEndian.Uint64(a[48:56]),
		binary.LittleEndian.Uint64(a[56:64]),
		binary.LittleEndian.Uint64(a[64:72]),
		binary.LittleEndian.Uint64(a[72:80]),
		binary.LittleEndian.Uint64(a[80:88]),
		binary.LittleEndian.Uint64(a[88:96]),
	}
	// d0*r2 + d1*r3
	d0.Mul(d0, &R2)
	d1.Mul(d1, &R3)
	return f.Add(d0, d1)
}

// SetNat initialises an element from saferith.Nat
// The value is reduced by the modulus.
func (f *Fp) SetNat(bi *saferith.Nat) *Fp {
	var buffer [FieldBytes]byte
	t := new(saferith.Nat).SetNat(bi)
	t.Mod(t, FpModulus)
	t.FillBytes(buffer[:])
	copy(buffer[:], bitstring.ReverseBytes(buffer[:]))
	_, _ = f.SetBytes(&buffer)
	return f
}

// Set copies a into fp.
func (f *Fp) Set(a *Fp) *Fp {
	f[0] = a[0]
	f[1] = a[1]
	f[2] = a[2]
	f[3] = a[3]
	f[4] = a[4]
	f[5] = a[5]
	return f
}

// SetLimbs converts an array into a field element
// by converting to montgomery form.
func (f *Fp) SetLimbs(a *[Limbs]uint64) *Fp {
	return f.toMontgomery((*Fp)(a))
}

// SetRaw converts a raw array into a field element
// Assumes input is already in montgomery form.
func (f *Fp) SetRaw(a *[Limbs]uint64) *Fp {
	f[0] = a[0]
	f[1] = a[1]
	f[2] = a[2]
	f[3] = a[3]
	f[4] = a[4]
	f[5] = a[5]
	return f
}

// Bytes converts a field element to a little endian byte array.
func (f *Fp) Bytes() [FieldBytes]byte {
	var out [FieldBytes]byte
	t := new(Fp).fromMontgomery(f)
	binary.LittleEndian.PutUint64(out[:8], t[0])
	binary.LittleEndian.PutUint64(out[8:16], t[1])
	binary.LittleEndian.PutUint64(out[16:24], t[2])
	binary.LittleEndian.PutUint64(out[24:32], t[3])
	binary.LittleEndian.PutUint64(out[32:40], t[4])
	binary.LittleEndian.PutUint64(out[40:], t[5])
	return out
}

// Nat converts this element into the saferith.Nat struct.
func (f *Fp) Nat() *saferith.Nat {
	buffer := f.Bytes()
	return new(saferith.Nat).SetBytes(bitstring.ReverseBytes(buffer[:]))
}

// Raw converts this element into the a [FieldLimbs]uint64.
func (f *Fp) Raw() [Limbs]uint64 {
	t := new(Fp).fromMontgomery(f)
	return *t
}

// CMove performs conditional select.
// selects arg1 if choice == 0 and arg2 if choice == 1.
func (f *Fp) CMove(arg1, arg2 *Fp, choice int) *Fp {
	mask := uint64(-choice)
	f[0] = arg1[0] ^ ((arg1[0] ^ arg2[0]) & mask)
	f[1] = arg1[1] ^ ((arg1[1] ^ arg2[1]) & mask)
	f[2] = arg1[2] ^ ((arg1[2] ^ arg2[2]) & mask)
	f[3] = arg1[3] ^ ((arg1[3] ^ arg2[3]) & mask)
	f[4] = arg1[4] ^ ((arg1[4] ^ arg2[4]) & mask)
	f[5] = arg1[5] ^ ((arg1[5] ^ arg2[5]) & mask)
	return f
}

// CNeg conditionally negates a if choice == 1.
func (f *Fp) CNeg(a *Fp, choice int) *Fp {
	var t Fp
	t.Neg(a)
	return f.CMove(f, &t, choice)
}

// Exp raises base^exp.
func (f *Fp) Exp(base, exp *Fp) *Fp {
	e := (&Fp{}).fromMontgomery(exp)
	return f.pow(base, e)
}

func (f *Fp) pow(base, e *Fp) *Fp {
	var tmp, res Fp
	res.SetOne()

	for i := len(e) - 1; i >= 0; i-- {
		for j := 63; j >= 0; j-- {
			res.Square(&res)
			tmp.Mul(&res, base)
			res.CMove(&res, &tmp, int(e[i]>>j)&1)
		}
	}
	f[0] = res[0]
	f[1] = res[1]
	f[2] = res[2]
	f[3] = res[3]
	f[4] = res[4]
	f[5] = res[5]
	return f
}

// montReduce performs the montgomery reduction.
func (f *Fp) montReduce(r *[2 * Limbs]uint64) *Fp {
	// Taken from Algorithm 14.32 in Handbook of Applied Cryptography
	var r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, carry, k uint64
	var rr Fp

	k = r[0] * inv
	_, carry = mac(r[0], k, FpModulusLimbs[0], 0)
	r1, carry = mac(r[1], k, FpModulusLimbs[1], carry)
	r2, carry = mac(r[2], k, FpModulusLimbs[2], carry)
	r3, carry = mac(r[3], k, FpModulusLimbs[3], carry)
	r4, carry = mac(r[4], k, FpModulusLimbs[4], carry)
	r5, carry = mac(r[5], k, FpModulusLimbs[5], carry)
	r6, r7 = adc(r[6], 0, carry)

	k = r1 * inv
	_, carry = mac(r1, k, FpModulusLimbs[0], 0)
	r2, carry = mac(r2, k, FpModulusLimbs[1], carry)
	r3, carry = mac(r3, k, FpModulusLimbs[2], carry)
	r4, carry = mac(r4, k, FpModulusLimbs[3], carry)
	r5, carry = mac(r5, k, FpModulusLimbs[4], carry)
	r6, carry = mac(r6, k, FpModulusLimbs[5], carry)
	r7, r8 = adc(r7, r[7], carry)

	k = r2 * inv
	_, carry = mac(r2, k, FpModulusLimbs[0], 0)
	r3, carry = mac(r3, k, FpModulusLimbs[1], carry)
	r4, carry = mac(r4, k, FpModulusLimbs[2], carry)
	r5, carry = mac(r5, k, FpModulusLimbs[3], carry)
	r6, carry = mac(r6, k, FpModulusLimbs[4], carry)
	r7, carry = mac(r7, k, FpModulusLimbs[5], carry)
	r8, r9 = adc(r8, r[8], carry)

	k = r3 * inv
	_, carry = mac(r3, k, FpModulusLimbs[0], 0)
	r4, carry = mac(r4, k, FpModulusLimbs[1], carry)
	r5, carry = mac(r5, k, FpModulusLimbs[2], carry)
	r6, carry = mac(r6, k, FpModulusLimbs[3], carry)
	r7, carry = mac(r7, k, FpModulusLimbs[4], carry)
	r8, carry = mac(r8, k, FpModulusLimbs[5], carry)
	r9, r10 = adc(r9, r[9], carry)

	k = r4 * inv
	_, carry = mac(r4, k, FpModulusLimbs[0], 0)
	r5, carry = mac(r5, k, FpModulusLimbs[1], carry)
	r6, carry = mac(r6, k, FpModulusLimbs[2], carry)
	r7, carry = mac(r7, k, FpModulusLimbs[3], carry)
	r8, carry = mac(r8, k, FpModulusLimbs[4], carry)
	r9, carry = mac(r9, k, FpModulusLimbs[5], carry)
	r10, r11 = adc(r10, r[10], carry)

	k = r5 * inv
	_, carry = mac(r5, k, FpModulusLimbs[0], 0)
	rr[0], carry = mac(r6, k, FpModulusLimbs[1], carry)
	rr[1], carry = mac(r7, k, FpModulusLimbs[2], carry)
	rr[2], carry = mac(r8, k, FpModulusLimbs[3], carry)
	rr[3], carry = mac(r9, k, FpModulusLimbs[4], carry)
	rr[4], carry = mac(r10, k, FpModulusLimbs[5], carry)
	rr[5], _ = adc(r11, r[11], carry)

	return f.Sub(&rr, &FpModulusLimbs)
}
