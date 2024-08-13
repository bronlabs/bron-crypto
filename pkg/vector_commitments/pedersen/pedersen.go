package vpedersencomm

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	vectorcommitments "github.com/copperexchange/krypton-primitives/pkg/vector_commitments"
	"io"
)

var (
	_ vectorcommitments.Element    = Element(nil)
	_ vectorcommitments.Commitment = Commitment(nil)
	_ vectorcommitments.Opening    = Opening(nil)

	_ vectorcommitments.Scheme[Commitment, Element, Opening] = (*Scheme)(nil)
)

type Element = curves.Scalar
type Commitment = curves.Point
type Opening = curves.Scalar

type Scheme struct {
	gs []curves.Point
	h  curves.Point
}

func NewScheme(gs []curves.Point, h curves.Point) *Scheme {
	return &Scheme{
		gs: gs,
		h:  h,
	}
}

func (s *Scheme) RandomOpening(prng io.Reader) (Opening, error) {
	r, err := s.h.Curve().ScalarField().Random(prng)
	if err != nil {
		return nil, errs.NewRandomSample("cannot sample point")
	}

	return r, nil
}

func (s *Scheme) CommitWithOpening(vector []Element, opening Opening) (Commitment, error) {
	if len(vector) != len(s.gs) {
		return nil, errs.NewFailed("invalid vector length")
	}

	c := s.h.Curve().AdditiveIdentity()
	for i, g := range s.gs {
		gm := g.ScalarMul(vector[i])
		c = c.Add(gm)
	}
	hr := s.h.ScalarMul(opening)
	c = c.Add(hr)

	return c, nil
}

func (s *Scheme) Commit(vector []Element, prng io.Reader) (Commitment, Opening, error) {
	r, err := s.RandomOpening(prng)
	if err != nil {
		return nil, nil, errs.NewRandomSample("cannot sample point")
	}

	c, err := s.CommitWithOpening(vector, r)
	if err != nil {
		return nil, nil, errs.NewRandomSample("cannot sample opening")
	}

	return c, r, nil
}

func (s *Scheme) Verify(vector []Element, commitment Commitment, opening Opening) error {
	if len(vector) == 0 || commitment == nil || opening == nil {
		return errs.NewVerification("verification failed")
	}

	c, err := s.CommitWithOpening(vector, opening)
	if err != nil {
		return errs.WrapVerification(err, "verification failed")
	}

	if !s.CommitmentEqual(commitment, c) {
		return errs.NewVerification("verification failed")
	}

	return nil
}

func (*Scheme) CommitmentEqual(lhs, rhs Commitment) bool {
	if lhs == nil || rhs == nil {
		return lhs == rhs
	}

	return lhs.Equal(rhs)
}
