package pedersenvectorcommitments

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	vc "github.com/copperexchange/krypton-primitives/pkg/vector_commitments"
)

var _ vc.VectorCommitter[VectorElement, *VectorCommitment, Vector, *Opening] = (*VectorCommitter)(nil)

type VectorCommitter struct {
	sessionId []byte
	h         curves.Point
	prng      io.Reader
	g         []curves.Point
	*vectorHomomorphicScheme
}

// not UC-secure without session-id.
func NewVectorCommitter(sessionId []byte, curve curves.Curve, vectorLength uint, prng io.Reader) (*VectorCommitter, error) {
	if curve == nil {
		return nil, errs.NewIsNil("curve is nil")
	}
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	if vectorLength == 0 {
		return nil, errs.NewArgument("vector length shall be greater than 0")
	}
	g, err := sampleGenerators(sessionId, curve, vectorLength)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate generators")
	}
	return &VectorCommitter{
		sessionId:               sessionId,
		h:                       curve.Generator(),
		prng:                    prng,
		g:                       g,
		vectorHomomorphicScheme: scheme,
	}, nil
}

func (c *VectorCommitter) Commit(vector Vector) (*VectorCommitment, *Opening, error) {
	curve := c.h.Curve()
	witness, err := curve.ScalarField().Random(c.prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not draw the witness at random")
	}
	commitment := curve.Generator().ScalarMul(witness)
	for i, msg := range vector {
		commitment = commitment.Add(c.g[i].ScalarMul(msg))
	}
	return &VectorCommitment{
			value: commitment,
		},
		&Opening{
			vector:  vector,
			witness: witness,
		},
		nil
}

func (*VectorCommitter) OpenAtIndex(index uint, vector Vector, fullOpening *Opening) (commitments.Opening[VectorElement], error) {
	panic("implement me")
}
