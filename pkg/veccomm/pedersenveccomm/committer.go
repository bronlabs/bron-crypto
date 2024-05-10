package pedersenveccomm

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/comm"
	"github.com/copperexchange/krypton-primitives/pkg/veccomm"
)

var _ veccomm.VectorCommitter[Message, *VectorCommitment, *Opening] = (*VectorCommitter)(nil)

type VectorCommitter struct {
	sessionId []byte
	h         curves.Point
	prng      io.Reader
	*vectorHomomorphicScheme
}

// not UC-secure without session-id.
func NewVectorCommitter(sessionId []byte, curve curves.Curve, prng io.Reader) (*VectorCommitter, error) {
	if curve == nil {
		return nil, errs.NewIsNil("curve is nil")
	}
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	return &VectorCommitter{
		sessionId:               sessionId,
		h:                       curve.Generator(),
		prng:                    prng,
		vectorHomomorphicScheme: scheme,
	}, nil
}

func (c *VectorCommitter) Commit(vector Vector) (*VectorCommitment, *Opening, error) {
	curve := c.h.Curve()
	witness, err := curve.ScalarField().Random(c.prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not draw the witness at random")
	}
	g, err := c.sampleGenerators(c.sessionId, curve, uint(len(vector)))
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not generate generators")
	}
	commitment := curve.Generator().ScalarMul(witness)
	for i, msg := range vector {
		commitment = commitment.Add(g[i].ScalarMul(msg))
	}
	return &VectorCommitment{
			value:  commitment,
			length: uint(len(vector)),
		},
		&Opening{
			vector:  vector,
			witness: witness,
		},
		nil
}

func (*VectorCommitter) OpenAtIndex(index uint, vector Vector, fullOpening *Opening) (comm.Opening[Message], error) {
	panic("implement me")
}
