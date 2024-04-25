package pedersen

import (
	crand "crypto/rand"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type Commitment struct {
	C curves.Point
}

type Opening struct {
	Messages []curves.Scalar
	Nonces   []curves.Scalar
}

type Committer struct {
	G, H curves.Point
}

type Verifier struct {
	G, H curves.Point
}

func NewCommitter(g, h curves.Point) *Committer {
	return &Committer{
		G: g,
		H: h,
	}
}

func NewVerifier(g, h curves.Point) *Verifier {
	return &Verifier{
		G: g,
		H: h,
	}
}

func (c *Committer) Commit(messages []curves.Scalar) (*Commitment, *Opening) {
	nonces := make([]curves.Scalar, len(messages))
	commitments := messages[0].ScalarField().Curve().AdditiveIdentity()
	for i, message := range messages {
		var err error
		nonces[i], err = messages[i].ScalarField().Random(crand.Reader)
		if err != nil {
			panic(err)
		}
		commitments = commitments.Add(c.G.Mul(message).Add(c.H.Mul(nonces[i])))
	}

	commitment := &Commitment{
		C: commitments,
	}
	opening := &Opening{
		Messages: messages,
		Nonces:   nonces,
	}

	return commitment, opening
}

func (v *Verifier) Verify(commitment *Commitment, opening *Opening) error {
	c := commitment.C.Curve().AdditiveIdentity()
	for i, message := range opening.Messages {
		c = c.Add(v.G.Mul(message).Add(v.H.Mul(opening.Nonces[i])))
	}

	if !c.Equal(commitment.C) {
		return errs.NewVerification("verification failed")
	}

	return nil
}
