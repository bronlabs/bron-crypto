package paillier

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

func NewPlaintextSpace(n *num.NatPlus) (*PlaintextSpace, error) {
	out, err := num.NewZMod(n)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create ZMod for plaintext space")
	}
	return (*PlaintextSpace)(out), nil
}

type PlaintextSpace num.ZMod

func (pts *PlaintextSpace) N() *num.NatPlus {
	return (*num.ZMod)(pts).Modulus()
}

func (pts *PlaintextSpace) Zero() *Plaintext {
	return &Plaintext{
		v: num.Z().Zero(),
		n: pts.N(),
	}
}

func (pts *PlaintextSpace) Sample(lowInclusive, highExclusive *Plaintext, prng io.Reader) (*Plaintext, error) {
	if lowInclusive == nil && highExclusive == nil {
		sampled, err := (*num.ZMod)(pts).Random(prng)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "failed to sample from plaintext space")
		}
		v, err := num.Z().FromUintSymmetric(sampled)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to create centered plaintext from nat")
		}
		return &Plaintext{
			v: v,
			n: pts.N(),
		}, nil
	}
	if lowInclusive != nil && highExclusive != nil {
		v, err := num.Z().Random(lowInclusive.Value(), highExclusive.Value(), prng)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "failed to sample from plaintext space")
		}
		return &Plaintext{
			v: v,
			n: pts.N(),
		}, nil
	}
	return nil, errs.NewFailed("must either be closed or open interval sampling")
}

func (pts *PlaintextSpace) Contains(m *Plaintext) bool {
	return m != nil && pts.N().Equal(m.N())
}

func (pts *PlaintextSpace) New(x *numct.Nat) (*Plaintext, error) {
	y, err := num.NewUintGivenModulus(x, pts.N().ModulusCT())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create plaintext from nat")
	}
	z, err := num.Z().FromUintSymmetric(y)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create centered plaintext from nat")
	}
	return &Plaintext{
		v: z,
		n: pts.N(),
	}, nil
}

type Plaintext struct {
	v *num.Int
	n *num.NatPlus
}

func (cp *Plaintext) Normalize() *num.Uint {
	return cp.v.Mod(cp.n)
}

func (cp *Plaintext) Value() *num.Int {
	return cp.v
}

func (cp *Plaintext) ValueCT() *numct.Int {
	return cp.Value().Value()
}

func (cp *Plaintext) N() *num.NatPlus {
	return cp.n
}

func (cp *Plaintext) isValid(x *Plaintext) {
	if x == nil {
		panic("cannot operate on nil centered plaintexts")
	}
	if !cp.n.Equal(x.n) {
		panic("cannot operate on centered plaintexts with different moduli")
	}
	if !x.v.IsInRange(cp.n) {
		panic("cannot operate on centered plaintexts with values out of range")
	}
}

func (cp *Plaintext) Op(other *Plaintext) *Plaintext {
	return cp.Add(other)
}

func (cp *Plaintext) Add(other *Plaintext) *Plaintext {
	cp.isValid(other)
	out, err := num.Z().FromUintSymmetric(cp.v.Mod(cp.n).Add(other.v.Mod(other.n)))
	if err != nil {
		panic(err)
	}
	return &Plaintext{v: out, n: cp.n}
}

func (cp *Plaintext) Equal(other *Plaintext) bool {
	return cp.Value().Equal(other.Value())
}

func (cp *Plaintext) OpInv() *Plaintext {
	return cp.Neg()
}

func (cp *Plaintext) Neg() *Plaintext {
	out, err := num.Z().FromUintSymmetric(cp.v.Mod(cp.n).Neg())
	if err != nil {
		panic(err)
	}
	return &Plaintext{v: out, n: cp.n}
}

func (cp *Plaintext) Sub(other *Plaintext) *Plaintext {
	cp.isValid(other)
	out, err := num.Z().FromUintSymmetric(cp.v.Mod(cp.n).Sub(other.v.Mod(other.n)))
	if err != nil {
		panic(err)
	}
	return &Plaintext{v: out, n: cp.n}
}

func (cp *Plaintext) IsLessThanOrEqual(other *Plaintext) bool {
	return other != nil && cp.n.Equal(other.n) && cp.v.IsLessThanOrEqual(other.v)
}

func (cp *Plaintext) PartialCompare(other *Plaintext) base.PartialOrdering {
	if other == nil || !cp.n.Equal(other.n) {
		return base.Incomparable
	}
	return base.PartialOrdering(cp.v.Compare(other.v))
}
