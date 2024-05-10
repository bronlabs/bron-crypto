package pedersenveccomm

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/comm"
	"github.com/copperexchange/krypton-primitives/pkg/veccomm"
)

var _ veccomm.VectorVerifier[Message, *VectorCommitment, *Opening] = (*VectorVerifier)(nil)

type VectorVerifier struct {
	sessionId []byte
	h         curves.Point
	*vectorHomomorphicScheme
}

// not UC-secure without session-id.
func NewVectorVerifier(sessionId []byte, curve curves.Curve) (*VectorVerifier, error) {
	if curve == nil {
		return nil, errs.NewIsNil("curve is nil")
	}
	return &VectorVerifier{
		sessionId:               sessionId,
		h:                       curve.Generator(),
		vectorHomomorphicScheme: scheme,
	}, nil
}

func (v *VectorVerifier) Verify(vectorCommitment *VectorCommitment, opening *Opening) error {
	if err := vectorCommitment.Validate(); err != nil {
		return errs.WrapFailed(err, "unvalid commitment")
	}
	if err := opening.Validate(); err != nil {
		return errs.WrapFailed(err, "unvalid opening")
	}
	curve := v.h.Curve()
	g, err := v.sampleGenerators(v.sessionId, curve, vectorCommitment.length)
	if err != nil {
		return errs.WrapFailed(err, "could not generate generators")
	}
	localCommitment := curve.Generator().ScalarMul(opening.witness)
	for i, msg := range opening.vector {
		localCommitment = localCommitment.Add(g[i].ScalarMul(msg))
	}
	if !vectorCommitment.value.Equal(localCommitment) {
		return errs.NewVerification("verification failed")
	}
	return nil
}

func (*VectorVerifier) VerifyAtIndex(index uint, vector Vector, opening comm.Opening[Message]) error {
	panic("implement me")
}
