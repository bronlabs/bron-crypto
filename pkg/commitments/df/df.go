package df

import (
	crand "crypto/rand"
	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/cronokirby/saferith"
	"io"
	"math/big"
)

var (
	_ commitments.Message    = (*Message)(nil)
	_ commitments.Witness    = (*Witness)(nil)
	_ commitments.Scalar     = (*Scalar)(nil)
	_ commitments.Commitment = (*Commitment)(nil)

	_ commitments.HomomorphicScheme[*Commitment, *Message, *Witness, *Scalar] = (*Scheme)(nil)
)

type Message = saferith.Int
type Witness = saferith.Int
type Scalar = saferith.Int
type Commitment = saferith.Nat

type Scheme struct {
	g *saferith.Nat
	h *saferith.Nat
	n *saferith.Modulus
}

func NewScheme(g, h *saferith.Nat, n *saferith.Modulus) *Scheme {
	return &Scheme{
		g: g,
		h: h,
		n: n,
	}
}

func (s *Scheme) RandomWitness(prng io.Reader) *Witness {
	witnessBound := new(big.Int)
	witnessBound.SetBit(witnessBound, s.n.BitLen()+base.ComputationalSecurity, 1)
	witnessBig, err := crand.Int(prng, witnessBound)
	if err != nil {
		panic(err)
	}
	witness := new(saferith.Int).SetBig(witnessBig, s.n.BitLen()+base.ComputationalSecurity)
	return witness
}

func (s *Scheme) CommitWithWitness(message *Message, witness *Witness) *Commitment {
	gm := new(saferith.Nat).ExpI(s.g, message, s.n)
	hr := new(saferith.Nat).ExpI(s.h, witness, s.n)
	c := new(saferith.Nat).ModMul(gm, hr, s.n)
	return c
}

func (s *Scheme) Commit(message *Message, prng io.Reader) (*Commitment, *Witness) {
	witness := s.RandomWitness(prng)
	return s.CommitWithWitness(message, witness), witness
}

func (s *Scheme) Verify(message *Message, commitment *Commitment, witness *Witness) error {
	if message == nil || commitment == nil || witness == nil {
		return errs.NewVerification("verification failed")
	}

	rhs := s.CommitWithWitness(message, witness)
	if s.IsEqual(commitment, rhs) {
		return nil
	}

	return errs.NewVerification("verification failed")
}

func (s *Scheme) IsEqual(lhs, rhs *Commitment) bool {
	if lhs == nil || rhs == nil {
		return lhs == rhs
	}

	return lhs.Eq(rhs) == 1
}

func (s *Scheme) CommitmentSum(x *Commitment, ys ...*Commitment) *Commitment {
	sum := x.Clone()
	for _, y := range ys {
		sum = s.CommitmentAdd(sum, y)
	}
	return sum
}

func (s *Scheme) CommitmentAdd(x, y *Commitment) *Commitment {
	return new(saferith.Nat).ModMul(x, y, s.n)
}

func (s *Scheme) CommitmentSub(x, y *Commitment) *Commitment {
	yInv := new(saferith.Nat).ModInverse(y, s.n)
	return new(saferith.Nat).ModMul(x, yInv, s.n)
}

func (s *Scheme) CommitmentNeg(x *Commitment) *Commitment {
	xInv := new(saferith.Nat).ModInverse(x, s.n)
	return xInv
}

func (s *Scheme) CommitmentScale(x *Commitment, sc *Scalar) *Commitment {
	return new(saferith.Nat).ExpI(x, sc, s.n)
}

func (s *Scheme) WitnessSum(x *Witness, ys ...*Witness) *Witness {
	sum := x.Clone()
	for _, y := range ys {
		sum = s.WitnessAdd(sum, y)
	}
	return sum
}

func (s *Scheme) WitnessAdd(x, y *Witness) *Witness {
	return new(saferith.Int).Add(x, y, -1)
}

func (s *Scheme) WitnessSub(x, y *Witness) *Witness {
	return new(saferith.Int).Add(x, s.WitnessNeg(y), -1)
}

func (s *Scheme) WitnessNeg(x *Witness) *Witness {
	return new(saferith.Int).SetInt(x).Neg(1)
}

func (s *Scheme) WitnessScale(x *Witness, sc *Scalar) *Witness {
	return new(saferith.Int).Mul(x, sc, -1)
}
