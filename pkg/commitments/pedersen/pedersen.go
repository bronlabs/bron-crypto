package pedersencommitment

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"io"
)

var (
	_ commitments.Message    = Message(nil)
	_ commitments.Opening    = Opening(nil)
	_ commitments.Scalar     = Scalar(nil)
	_ commitments.Commitment = Commitment(nil)

	_ commitments.HomomorphicScheme[Commitment, Message, Opening, Scalar] = (*Scheme)(nil)
)

type Message curves.Scalar
type Opening curves.Scalar
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

func (s *Scheme) RandomOpening(prng io.Reader) (Opening, error) {
	curve := s.g.Curve()
	w, err := curve.ScalarField().Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot sample opening")
	}
	return w, nil
}

func (s *Scheme) CommitWithOpening(message Message, witness Opening) (Commitment, error) {
	gm := s.g.ScalarMul(message)
	hr := s.h.ScalarMul(witness)
	c := gm.Add(hr)
	return c, nil
}

func (s *Scheme) Commit(message Message, prng io.Reader) (Commitment, Opening, error) {
	witness, err := s.RandomOpening(prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample opening")
	}
	commitment, err := s.CommitWithOpening(message, witness)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot compute commitment")
	}
	return commitment, witness, nil
}

func (s *Scheme) Verify(message Message, commitment Commitment, witness Opening) error {
	if message == nil || commitment == nil || witness == nil {
		return errs.NewVerification("verification failed")
	}

	rhs, err := s.CommitWithOpening(message, witness)
	if err != nil {
		return errs.WrapVerification(err, "verification failed")
	}
	if !s.IsEqual(commitment, rhs) {
		return errs.NewVerification("verification failed")
	}

	return nil
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

func (*Scheme) CommitmentAdd(x, y Commitment) Commitment {
	return x.Add(y)
}

func (*Scheme) CommitmentSub(x, y Commitment) Commitment {
	return x.Sub(y)
}

func (*Scheme) CommitmentNeg(x Commitment) Commitment {
	return x.Neg()
}

func (*Scheme) CommitmentScale(x Commitment, sc Scalar) Commitment {
	return x.ScalarMul(sc)
}

func (s *Scheme) OpeningSum(x Opening, ys ...Opening) Opening {
	sum := x.Clone()
	for _, y := range ys {
		sum = s.OpeningAdd(sum, y)
	}
	return sum
}

func (*Scheme) OpeningAdd(x, y Opening) Opening {
	return x.Add(y)
}

func (*Scheme) OpeningSub(x, y Opening) Opening {
	return x.Sub(y)
}

func (*Scheme) OpeningNeg(x Opening) Opening {
	return x.Neg()
}

func (*Scheme) OpeningScale(x Opening, sc Scalar) Opening {
	return x.Mul(sc)
}
