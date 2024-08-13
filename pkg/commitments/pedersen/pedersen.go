package pedersencommitment

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"io"
)

var (
	_ commitments.Message    = Message(nil)
	_ commitments.Witness    = Witness(nil)
	_ commitments.Scalar     = Scalar(nil)
	_ commitments.Commitment = Commitment(nil)

	_ commitments.HomomorphicScheme[Commitment, Message, Witness, Scalar] = (*Scheme)(nil)
)

type Message curves.Scalar
type Witness curves.Scalar
type Scalar curves.Scalar
type Commitment curves.Point

type Scheme struct {
	g curves.Point
	h curves.Point
}

func NewScheme(g, h curves.Point) *Scheme {
	return &Scheme{
		g: g,
		h: h,
	}
}

func (s *Scheme) RandomWitness(prng io.Reader) Witness {
	curve := s.g.Curve()
	w, err := curve.ScalarField().Random(prng)
	if err != nil {
		panic(err)
	}
	return w
}

func (s *Scheme) CommitWithWitness(message Message, witness Witness) Commitment {
	gm := s.g.ScalarMul(message)
	hr := s.h.ScalarMul(witness)
	c := gm.Add(hr)
	return c
}

func (s *Scheme) Commit(message Message, prng io.Reader) (Commitment, Witness) {
	witness := s.RandomWitness(prng)
	return s.CommitWithWitness(message, witness), witness
}

func (s *Scheme) Verify(message Message, commitment Commitment, witness Witness) error {
	if message == nil || commitment == nil || witness == nil {
		return errs.NewVerification("verification failed")
	}

	rhs := s.CommitWithWitness(message, witness)
	if s.IsEqual(commitment, rhs) {
		return nil
	}

	return errs.NewVerification("verification failed")
}

func (s *Scheme) IsEqual(lhs, rhs Commitment) bool {
	if lhs == nil || rhs == nil {
		return rhs == lhs
	}

	return lhs.Equal(rhs)
}

func (s *Scheme) CommitmentSum(x Commitment, ys ...Commitment) Commitment {
	sum := x.Clone()
	for _, y := range ys {
		sum = s.CommitmentAdd(sum, y)
	}
	return sum
}

func (s *Scheme) CommitmentAdd(x, y Commitment) Commitment {
	return x.Add(y)
}

func (s *Scheme) CommitmentSub(x, y Commitment) Commitment {
	return x.Sub(y)
}

func (s *Scheme) CommitmentNeg(x Commitment) Commitment {
	return x.Neg()
}

func (s *Scheme) CommitmentScale(x Commitment, sc Scalar) Commitment {
	return x.ScalarMul(sc)
}

func (s *Scheme) WitnessSum(x Witness, ys ...Witness) Witness {
	sum := x.Clone()
	for _, y := range ys {
		sum = s.WitnessAdd(sum, y)
	}
	return sum
}

func (s *Scheme) WitnessAdd(x, y Witness) Witness {
	return x.Add(y)
}

func (s *Scheme) WitnessSub(x, y Witness) Witness {
	return x.Sub(y)
}

func (s *Scheme) WitnessNeg(x Witness) Witness {
	return x.Neg()
}

func (s *Scheme) WitnessScale(x Witness, sc Scalar) Witness {
	return x.Mul(sc)
}
