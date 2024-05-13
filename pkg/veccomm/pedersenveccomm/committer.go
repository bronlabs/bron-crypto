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
	g    curves.Point
	hs   []curves.Point
	prng io.Reader
	*vectorHomomorphicScheme
}

func NewVectorCommitter(sessionId []byte, curve curves.Curve, n uint, prng io.Reader) (*VectorCommitter, error) {
	if curve == nil {
		return nil, errs.NewIsNil("curve is nil")
	}
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}

	g := curve.Generator()
	hs, err := scheme.sampleGenerators(sessionId, curve, n)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate generators")
	}

	committer := &VectorCommitter{
		g:                       g,
		hs:                      hs,
		prng:                    prng,
		vectorHomomorphicScheme: scheme,
	}

	return committer, nil
}

func (c *VectorCommitter) Commit(vector Vector) (*VectorCommitment, *Opening, error) {
	if len(vector) != len(c.hs) {
		return nil, nil, errs.NewSize("invalid vector length")
	}

	witness, err := c.g.Curve().ScalarField().Random(c.prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not draw the witness at random")
	}

	vc := c.g.ScalarMul(witness)
	for i, msg := range vector {
		vc = vc.Add(c.hs[i].ScalarMul(msg))
	}

	commitment := &VectorCommitment{
		value: vc,
	}
	opening := &Opening{
		vector:  vector,
		witness: witness,
	}

	return commitment, opening, nil
}

func (*VectorCommitter) OpenAtIndex(index uint, vector Vector, fullOpening *Opening) (comm.Opening[Message], error) {
	panic("implement me")
}
