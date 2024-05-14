package hashvectorcommitments

import (
	"bytes"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	hashcommitments "github.com/copperexchange/krypton-primitives/pkg/commitments/hash"
	vectorcommitments "github.com/copperexchange/krypton-primitives/pkg/vector_commitments"
)

var _ vectorcommitments.VectorVerifier[hashcommitments.Message, *VectorCommitment, *Opening] = (*VectorVerifier)(nil)

type VectorVerifier struct {
	verifier *hashcommitments.Verifier
}

// not UC-secure without session-id.
func NewVectorVerifier(sessionId []byte) *VectorVerifier {
	verifier := hashcommitments.NewVerifier(sessionId)
	return &VectorVerifier{
		verifier: verifier,
	}
}

func (v *VectorVerifier) Verify(vectorCommitment *VectorCommitment, opening *Opening) error {
	if err := vectorCommitment.Validate(); err != nil {
		return errs.WrapFailed(err, "commitment invalid")
	}
	if err := opening.Validate(); err != nil {
		return errs.WrapFailed(err, "opening invalid")
	}
	if int(vectorCommitment.length) != len(opening.vector) {
		return errs.NewVerification("length does not match")
	}
	if !(bytes.Equal(encode(opening.vector), opening.opening.Message())) {
		return errs.NewVerification("commitment is not tied to the vector")
	}
	err := v.verifier.Verify(vectorCommitment.commitment, opening.opening)
	if err != nil {
		return errs.NewVerification("verification failed")
	}
	return nil
}

func (*VectorVerifier) VerifyAtIndex(index uint, vector vectorcommitments.Vector[hashcommitments.Message], opening commitments.Opening[hashcommitments.Message]) error {
	panic("implement me")
}
