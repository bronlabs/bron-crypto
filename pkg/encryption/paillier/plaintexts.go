package paillier

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/errs-go/errs"
)

// NewPlaintextSpace creates a new plaintext space Z_n for Paillier encryption.
// The space represents integers modulo n, where n is the RSA modulus.
func NewPlaintextSpace(n *num.NatPlus) (*PlaintextSpace, error) {
	out, err := num.NewZMod(n)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return (*PlaintextSpace)(out), nil
}

// PlaintextSpace represents the space of Paillier plaintexts modulo n.
// Plaintexts are centred integers in the range [-n/2, n/2).
type PlaintextSpace num.ZMod

// N returns the modulus n of the plaintext space.
func (pts *PlaintextSpace) N() *num.NatPlus {
	return (*num.ZMod)(pts).Modulus()
}

// Zero returns the zero plaintext (additive identity).
func (pts *PlaintextSpace) Zero() *Plaintext {
	return &Plaintext{
		v: num.Z().Zero(),
		n: pts.N(),
	}
}

// Sample samples a random plaintext from the plaintext space.
// If both bounds are nil, samples uniformly from the full range [-n/2, n/2).
// If both bounds are provided, samples uniformly from [lowInclusive, highExclusive).
func (pts *PlaintextSpace) Sample(lowInclusive, highExclusive *Plaintext, prng io.Reader) (*Plaintext, error) {
	if lowInclusive == nil && highExclusive == nil {
		sampled, err := (*num.ZMod)(pts).Random(prng)
		if err != nil {
			return nil, errs.Wrap(err)
		}
		v, err := num.Z().FromUintSymmetric(sampled)
		if err != nil {
			return nil, errs.Wrap(err)
		}
		return &Plaintext{
			v: v,
			n: pts.N(),
		}, nil
	}
	if lowInclusive != nil && highExclusive != nil {
		v, err := num.Z().Random(lowInclusive.Value(), highExclusive.Value(), prng)
		if err != nil {
			return nil, errs.Wrap(err)
		}
		return &Plaintext{
			v: v,
			n: pts.N(),
		}, nil
	}
	return nil, ErrInvalidRange.WithMessage("must either be closed or open interval sampling")
}

// Contains returns true if the plaintext belongs to this plaintext space.
func (pts *PlaintextSpace) Contains(m *Plaintext) bool {
	return m != nil && pts.N().Equal(m.N())
}

// FromNat creates a plaintext from a constant-time natural number.
// The value is reduced modulo n and centred to the symmetric range.
func (pts *PlaintextSpace) FromNat(x *numct.Nat) (*Plaintext, error) {
	y, err := num.NewUintGivenModulus(x, pts.N().ModulusCT())
	if err != nil {
		return nil, errs.Wrap(err)
	}
	z, err := num.Z().FromUintSymmetric(y)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return &Plaintext{
		v: z,
		n: pts.N(),
	}, nil
}

// FromBytes creates a plaintext from a byte slice.
// The bytes are interpreted as a big-endian unsigned integer.
func (pts *PlaintextSpace) FromBytes(b []byte) (*Plaintext, error) {
	var x numct.Nat
	if ok := x.SetBytes(b); ok == ct.False {
		return nil, errs.New("failed to create nat from bytes")
	}
	return pts.FromNat(&x)
}

// FromInt creates a plaintext from a constant-time signed integer.
// Returns an error if the value is outside the valid range [-n/2, n/2).
func (pts *PlaintextSpace) FromInt(x *numct.Int) (*Plaintext, error) {
	y, err := num.Z().FromIntCT(x)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	if !y.IsInRangeSymmetric(pts.N()) {
		return nil, ErrInvalidRange.WithMessage("int is out of range for plaintext space")
	}
	return &Plaintext{
		v: y,
		n: pts.N(),
	}, nil
}

// Plaintext represents a Paillier plaintext as a centred integer in [-n/2, n/2).
// This centred representation allows for both positive and negative values.
type Plaintext struct {
	v *num.Int
	n *num.NatPlus
}

// Normalise returns the plaintext value reduced to the range [0, n).
func (pt *Plaintext) Normalise() *num.Uint {
	return pt.v.Mod(pt.n)
}

// Value returns the centred integer value of the plaintext.
func (pt *Plaintext) Value() *num.Int {
	return pt.v
}

// ValueCT returns the plaintext value as a constant-time signed integer.
func (pt *Plaintext) ValueCT() *numct.Int {
	return pt.Value().Value()
}

// N returns the modulus n of the plaintext.
func (pt *Plaintext) N() *num.NatPlus {
	return pt.n
}

func (pt *Plaintext) isValid(x *Plaintext) {
	if x == nil {
		panic("cannot operate on nil centred plaintexts")
	}
	if !pt.n.Equal(x.n) {
		panic("cannot operate on centred plaintexts with different moduli")
	}
	if !x.v.IsInRangeSymmetric(pt.n) {
		panic("cannot operate on centred plaintexts with values out of range")
	}
}

// Op performs the group operation on two plaintexts (addition modulo n).
func (pt *Plaintext) Op(other *Plaintext) *Plaintext {
	return pt.Add(other)
}

// Add adds two plaintexts and returns the result reduced to the centred range.
func (pt *Plaintext) Add(other *Plaintext) *Plaintext {
	pt.isValid(other)
	out, err := num.Z().FromUintSymmetric(pt.v.Mod(pt.n).Add(other.v.Mod(other.n)))
	if err != nil {
		panic(err)
	}
	return &Plaintext{v: out, n: pt.n}
}

// Equal returns true if two plaintexts have the same value.
func (pt *Plaintext) Equal(other *Plaintext) bool {
	return pt.Value().Equal(other.Value())
}

// OpInv returns the additive inverse of the plaintext.
func (pt *Plaintext) OpInv() *Plaintext {
	return pt.Neg()
}

// Neg returns the negation of the plaintext.
func (pt *Plaintext) Neg() *Plaintext {
	out, err := num.Z().FromUintSymmetric(pt.v.Mod(pt.n).Neg())
	if err != nil {
		panic(err)
	}
	return &Plaintext{v: out, n: pt.n}
}

// Sub subtracts another plaintext from this one and returns the result.
func (pt *Plaintext) Sub(other *Plaintext) *Plaintext {
	pt.isValid(other)
	out, err := num.Z().FromUintSymmetric(pt.v.Mod(pt.n).Sub(other.v.Mod(other.n)))
	if err != nil {
		panic(err)
	}
	return &Plaintext{v: out, n: pt.n}
}

// IsLessThanOrEqual returns true if this plaintext is less than or equal to another.
func (pt *Plaintext) IsLessThanOrEqual(other *Plaintext) bool {
	return other != nil && pt.n.Equal(other.n) && pt.v.IsLessThanOrEqual(other.v)
}

// PartialCompare compares two plaintexts and returns their ordering.
// Returns Incomparable if the plaintexts have different moduli.
func (pt *Plaintext) PartialCompare(other *Plaintext) base.PartialOrdering {
	if other == nil || !pt.n.Equal(other.n) {
		return base.Incomparable
	}
	return base.PartialOrdering(pt.v.Compare(other.v))
}

// Bytes returns the plaintext value as a big-endian byte slice.
func (pt *Plaintext) Bytes() []byte {
	return pt.Value().Bytes()
}
