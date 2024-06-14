package impl

import (
	"io"
	"slices"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/fourq/impl/internal"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

const (
	fqFieldLimbs     = 4
	fqFieldBytes     = 31
	fqWideFieldBytes = fqFieldBytes * 2
	fqFieldBits      = 246
	fqDivSteps       = ((49 * fqFieldBits) + 57) / 17
)

var (
	FqOne          Fq
	FqR2           Fq
	FqR3           Fq
	FqModulus      *saferith.Modulus
	FqModulusLimbs [fqFieldLimbs]uint64
)

type Fq internal.FqMontgomeryDomainFieldElement

//nolint:gochecknoinits // for backward compatibility
func init() {
	var mod [fqFieldLimbs + 1]uint64
	var modBytes [fqFieldBytes]byte

	internal.FqSetOne((*internal.FqMontgomeryDomainFieldElement)(&FqOne))
	internal.FqToMontgomery((*internal.FqMontgomeryDomainFieldElement)(&FqR2), (*internal.FqNonMontgomeryDomainFieldElement)(&FqOne))
	internal.FqToMontgomery((*internal.FqMontgomeryDomainFieldElement)(&FqR3), (*internal.FqNonMontgomeryDomainFieldElement)(&FqR2))

	internal.FqMsat(&mod)
	internal.FqToBytes(&modBytes, (*[fqFieldLimbs]uint64)(mod[:fqFieldLimbs]))
	slices.Reverse(modBytes[:])
	FqModulus = saferith.ModulusFromNat(new(saferith.Nat).SetBytes(modBytes[:]).Resize(fqFieldBits))
	copy(FqModulusLimbs[:], mod[:])
}

// IsZero returns 1 if fq == 0, 0 otherwise.
func (f *Fq) IsZero() uint64 {
	var t uint64

	internal.FqNonzero(&t, (*[fqFieldLimbs]uint64)(f))
	return ((t | -t) >> 63) ^ 1
}

// IsNonZero returns 1 if fq != 0, 0 otherwise.
func (f *Fq) IsNonZero() uint64 {
	var t uint64

	internal.FqNonzero(&t, (*[fqFieldLimbs]uint64)(f))
	return (t | -t) >> 63
}

// IsOne returns 1 if fq == 1, 0 otherwise.
func (f *Fq) IsOne() uint64 {
	var t uint64
	var one internal.FqMontgomeryDomainFieldElement

	internal.FqSetOne(&one)
	internal.FqSub(&one, &one, (*internal.FqMontgomeryDomainFieldElement)(f))
	internal.FqNonzero(&t, (*[fqFieldLimbs]uint64)(&one))
	return ((t | -t) >> 63) ^ 1
}

// Cmp returns -1 if f < rhs
// 0 if f == rhs
// 1 if f > rhs.
func (f *Fq) Cmp(rhs *Fq) int64 {
	var l, r internal.FqNonMontgomeryDomainFieldElement
	var order int64

	internal.FqFromMontgomery(&l, (*internal.FqMontgomeryDomainFieldElement)(f))
	internal.FqFromMontgomery(&r, (*internal.FqMontgomeryDomainFieldElement)(rhs))
	internal.FqCmpLimbs(&order, (*[fqFieldLimbs]uint64)(&l), (*[fqFieldLimbs]uint64)(&r))
	return order
}

// Equal returns 1 if fq == rhs, 0 otherwise.
func (f *Fq) Equal(rhs *Fq) uint64 {
	var t uint64
	var zero internal.FqMontgomeryDomainFieldElement

	internal.FqSub(&zero, (*internal.FqMontgomeryDomainFieldElement)(f), (*internal.FqMontgomeryDomainFieldElement)(rhs))
	internal.FqNonzero(&t, (*[fqFieldLimbs]uint64)(&zero))
	return ((t | -t) >> 63) ^ 1
}

// LexicographicallyLargest returns 1 if
// this element is strictly lexicographically larger than its negation
// 0 otherwise.
func (f *Fq) LexicographicallyLargest() uint64 {
	fNeg := new(Fq).Neg(f)
	t := uint64(f.Cmp(fNeg)) ^ 1
	return ((t | -t) >> 63) ^ 1
}

// SetOne fq = r.
func (f *Fq) SetOne() *Fq {
	internal.FqSetOne((*internal.FqMontgomeryDomainFieldElement)(f))
	return f
}

// SetZero fq = 0.
func (f *Fq) SetZero() *Fq {
	*f = Fq{}
	return f
}

// SetUint64 fq = rhs.
func (f *Fq) SetUint64(rhs uint64) *Fq {
	var x = internal.FqNonMontgomeryDomainFieldElement{rhs}

	internal.FqToMontgomery((*internal.FqMontgomeryDomainFieldElement)(f), &x)
	return f
}

// Random generates a random field element.
func (f *Fq) Random(prng io.Reader) (*Fq, error) {
	var t [fqWideFieldBytes]byte

	_, err := io.ReadFull(prng, t[:])
	if err != nil {
		return nil, errs.WrapRandomSample(err, "reader failed")
	}
	return f.SetBytesWide(&t), nil
}

// Neg performs modular negation.
func (f *Fq) Neg(a *Fq) *Fq {
	internal.FqOpp((*internal.FqMontgomeryDomainFieldElement)(f), (*internal.FqMontgomeryDomainFieldElement)(a))
	return f
}

// Square performs modular square.
func (f *Fq) Square(a *Fq) *Fq {
	internal.FqSquare((*internal.FqMontgomeryDomainFieldElement)(f), (*internal.FqMontgomeryDomainFieldElement)(a))
	return f
}

// Double this element.
func (f *Fq) Double(a *Fq) *Fq {
	return f.Add(a, a)
}

// Mul performs modular multiplication.
func (f *Fq) Mul(arg1, arg2 *Fq) *Fq {
	internal.FqMul((*internal.FqMontgomeryDomainFieldElement)(f), (*internal.FqMontgomeryDomainFieldElement)(arg1), (*internal.FqMontgomeryDomainFieldElement)(arg2))
	return f
}

// Add performs modular addition.
func (f *Fq) Add(arg1, arg2 *Fq) *Fq {
	internal.FqAdd((*internal.FqMontgomeryDomainFieldElement)(f), (*internal.FqMontgomeryDomainFieldElement)(arg1), (*internal.FqMontgomeryDomainFieldElement)(arg2))
	return f
}

// Sub performs modular subtraction.
func (f *Fq) Sub(arg1, arg2 *Fq) *Fq {
	internal.FqSub((*internal.FqMontgomeryDomainFieldElement)(f), (*internal.FqMontgomeryDomainFieldElement)(arg1), (*internal.FqMontgomeryDomainFieldElement)(arg2))
	return f
}

// Sqrt performs modular square root.
func (*Fq) Sqrt(a *Fq) (fRes *Fq, wasSquare uint64) {
	panic("implement me")
}

// Invert performs modular inverse.
func (f *Fq) Invert(a *Fq) (fRes *Fq, wasInverted uint64) {
	var precomp, h, v, r, out4, out5 [fqFieldLimbs]uint64
	var ff, g, out2, out3 [fqFieldLimbs + 1]uint64
	var out1, inverted uint64

	d := uint64(1)
	internal.FqDivstepPrecomp(&precomp)
	internal.FqFromMontgomery((*internal.FqNonMontgomeryDomainFieldElement)(g[:]), (*internal.FqMontgomeryDomainFieldElement)(a))
	internal.FqMsat(&ff)
	internal.FqSetOne((*internal.FqMontgomeryDomainFieldElement)(&r))

	for i := 0; i < fqDivSteps-(fqDivSteps%2); i += 2 {
		internal.FqDivstep(&out1, &out2, &out3, &out4, &out5, d, &ff, &g, &v, &r)
		internal.FqDivstep(&d, &ff, &g, &v, &r, out1, &out2, &out3, &out4, &out5)
	}
	if (fqDivSteps % 2) != 0 { // compile time if - always true
		internal.FqDivstep(&out1, &out2, &out3, &out4, &out5, d, &ff, &g, &v, &r)
		v = out4
		ff = out2
	}

	internal.FqOpp((*internal.FqMontgomeryDomainFieldElement)(&h), (*internal.FqMontgomeryDomainFieldElement)(&v))
	internal.FqCMove(&v, ff[fqFieldLimbs]>>63, &v, &h)
	internal.FqMul((*internal.FqMontgomeryDomainFieldElement)(f), (*internal.FqMontgomeryDomainFieldElement)(&v), (*internal.FqMontgomeryDomainFieldElement)(&precomp))
	internal.FqNonzero(&inverted, (*[fqFieldLimbs]uint64)(f))

	return f, (inverted | -inverted) >> 63
}

// SetBytes converts a little endian byte array into a field element
// return 0 if the bytes are not in the field, 1 if they are.
func (f *Fq) SetBytes(arg *[fqFieldBytes]byte) (fRes *Fq, mask uint64) {
	var t internal.FqNonMontgomeryDomainFieldElement
	var order int64

	internal.FqFromBytes((*[fqFieldLimbs]uint64)(&t), arg)
	internal.FqToMontgomery((*internal.FqMontgomeryDomainFieldElement)(f), &t)
	internal.FqCmpLimbs(&order, (*[fqFieldLimbs]uint64)(&t), &FqModulusLimbs)
	check := uint64(order ^ int64(-1))
	return f, ((check | -check) >> 63) ^ 1
}

func (f *Fq) SetBytesWide(a *[fqWideFieldBytes]byte) *Fq {
	var d1, d0 [fqFieldLimbs]uint64

	internal.FqFromBytes(&d0, (*[fqFieldBytes]uint8)(a[:fqFieldBytes]))
	internal.FqFromBytes(&d1, (*[fqFieldBytes]uint8)(a[fqFieldBytes:]))

	// d0*r2 + d1*r3
	internal.FqMul((*internal.FqMontgomeryDomainFieldElement)(&d0), (*internal.FqMontgomeryDomainFieldElement)(&d0), (*internal.FqMontgomeryDomainFieldElement)(&FqR2))
	internal.FqMul((*internal.FqMontgomeryDomainFieldElement)(&d1), (*internal.FqMontgomeryDomainFieldElement)(&d1), (*internal.FqMontgomeryDomainFieldElement)(&FqR3))
	internal.FqAdd((*internal.FqMontgomeryDomainFieldElement)(f), (*internal.FqMontgomeryDomainFieldElement)(&d0), (*internal.FqMontgomeryDomainFieldElement)(&d1))
	return f
}

// SetNat initialises an element from saferith.Nat
// The value is reduced by the modulus.
func (f *Fq) SetNat(bi *saferith.Nat) *Fq {
	var buffer [fqFieldBytes]byte
	t := new(saferith.Nat).SetNat(bi)
	t.Mod(t, FqModulus)
	t.FillBytes(buffer[:])
	slices.Reverse(buffer[:])

	internal.FqFromBytes((*[fqFieldLimbs]uint64)(f), &buffer)
	internal.FqToMontgomery((*internal.FqMontgomeryDomainFieldElement)(f), (*internal.FqNonMontgomeryDomainFieldElement)(f))
	return f
}

// Set copies arg into fq.
func (f *Fq) Set(arg *Fq) *Fq {
	*f = *arg
	return f
}

// SetLimbs converts an array into a field element
// by converting to montgomery form.
func (f *Fq) SetLimbs(a *[fqFieldLimbs]uint64) *Fq {
	internal.FqToMontgomery((*internal.FqMontgomeryDomainFieldElement)(f), (*internal.FqNonMontgomeryDomainFieldElement)(a))
	return f
}

// SetRaw converts a raw array into a field element
// Assumes input is already in montgomery form.
func (f *Fq) SetRaw(a *[fqFieldLimbs]uint64) *Fq {
	*f = *a
	return f
}

// Bytes converts a field element to a little endian byte array.
func (f *Fq) Bytes() [fqFieldBytes]byte {
	var out internal.FqNonMontgomeryDomainFieldElement
	var bytes [fqFieldBytes]byte

	internal.FqFromMontgomery(&out, (*internal.FqMontgomeryDomainFieldElement)(f))
	internal.FqToBytes(&bytes, (*[fqFieldLimbs]uint64)(&out))
	return bytes
}

// Nat converts this element into the saferith.Nat struct.
func (f *Fq) Nat() *saferith.Nat {
	buffer := f.Bytes()
	slices.Reverse(buffer[:])
	return new(saferith.Nat).SetBytes(buffer[:])
}

// Raw converts this element into the a [FieldLimbs]uint64.
func (f *Fq) Raw() [fqFieldLimbs]uint64 {
	return *f
}

func (f *Fq) Limbs() [fqFieldLimbs]uint64 {
	var out internal.FqNonMontgomeryDomainFieldElement

	internal.FqFromMontgomery(&out, (*internal.FqMontgomeryDomainFieldElement)(f))
	return out
}

// CMove performs conditional select.
// selects arg1 if choice == 0 and arg2 if choice == 1.
func (f *Fq) CMove(arg1, arg2 *Fq, choice uint64) *Fq {
	internal.FqCMove((*[fqFieldLimbs]uint64)(f), choice, (*[fqFieldLimbs]uint64)(arg1), (*[fqFieldLimbs]uint64)(arg2))
	return f
}

// CNeg conditionally negates a if choice == 1.
func (f *Fq) CNeg(a *Fq, choice uint64) *Fq {
	var t Fq
	t.Neg(a)
	return f.CMove(f, &t, choice)
}

// Exp raises base^exp.
func (f *Fq) Exp(base, exp *Fq) *Fq {
	var e internal.FqNonMontgomeryDomainFieldElement

	internal.FqFromMontgomery(&e, (*internal.FqMontgomeryDomainFieldElement)(exp))
	return f.pow(base, (*Fq)(&e))
}

func (f *Fq) pow(base, e *Fq) *Fq {
	var tmp, res Fq
	res.SetOne()

	for i := len(e) - 1; i >= 0; i-- {
		for j := 63; j >= 0; j-- {
			res.Square(&res)
			tmp.Mul(&res, base)
			res.CMove(&res, &tmp, (e[i]>>j)&1)
		}
	}

	*f = res
	return f
}
