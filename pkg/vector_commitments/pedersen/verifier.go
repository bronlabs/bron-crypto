package pedersenvectorcommitments

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	vc "github.com/bronlabs/bron-crypto/pkg/vector_commitments"
)

var _ vc.VectorVerifier[VectorElement, *VectorCommitment, Vector, *Opening] = (*VectorVerifier)(nil)

type VectorVerifier struct {
	sessionId []byte
	h         curves.Point
	g         []curves.Point
	*vectorHomomorphicScheme
}

// not UC-secure without session-id.
func NewVectorVerifier(sessionId []byte, curve curves.Curve, vectorLength uint) (*VectorVerifier, error) {
	if curve == nil {
		return nil, errs.NewIsNil("curve is nil")
	}
	if vectorLength == 0 {
		return nil, errs.NewArgument("vector length shall be greater than 0")
	}
	g, err := sampleGenerators(sessionId, curve, vectorLength)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate generators")
	}
	return &VectorVerifier{
		sessionId:               sessionId,
		h:                       curve.Generator(),
		g:                       g,
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
	localCommitment := curve.Generator().ScalarMul(opening.witness)
	for i, msg := range opening.vector {
		localCommitment = localCommitment.Add(v.g[i].ScalarMul(msg))
	}
	if !vectorCommitment.value.Equal(localCommitment) {
		return errs.NewVerification("verification failed")
	}
	return nil
}

func (*VectorVerifier) VerifyAtIndex(index uint, vector Vector, opening commitments.Opening[VectorElement]) error {
	panic("implement me")
}
