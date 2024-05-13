package pedersenveccomm

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/comm"
	"github.com/copperexchange/krypton-primitives/pkg/veccomm"
)

var _ veccomm.VectorVerifier[Message, *VectorCommitment, *Opening] = (*VectorVerifier)(nil)

type VectorVerifier struct {
	g  curves.Point
	hs []curves.Point
	*vectorHomomorphicScheme
}

func NewVectorVerifier(sessionId []byte, curve curves.Curve, n uint) (*VectorVerifier, error) {
	if curve == nil {
		return nil, errs.NewIsNil("curve is nil")
	}

	g := curve.Generator()
	hs, err := scheme.sampleGenerators(sessionId, curve, n)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate generators")
	}

	verifier := &VectorVerifier{
		g:                       g,
		hs:                      hs,
		vectorHomomorphicScheme: scheme,
	}
	return verifier, nil
}

func (v *VectorVerifier) Verify(vectorCommitment *VectorCommitment, opening *Opening) error {
	if err := vectorCommitment.Validate(); err != nil {
		return errs.WrapFailed(err, "unvalid commitment")
	}
	if err := opening.Validate(); err != nil {
		return errs.WrapFailed(err, "unvalid opening")
	}

	localCommitment := v.g.Curve().Generator().ScalarMul(opening.witness)
	for i, msg := range opening.vector {
		localCommitment = localCommitment.Add(v.hs[i].ScalarMul(msg))
	}
	if !vectorCommitment.value.Equal(localCommitment) {
		return errs.NewVerification("verification failed")
	}

	return nil
}

func (*VectorVerifier) VerifyAtIndex(index uint, vector Vector, opening comm.Opening[Message]) error {
	panic("implement me")
}
