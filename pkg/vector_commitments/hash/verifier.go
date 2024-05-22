package hashvectorcommitments

import (
	"bytes"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	vc "github.com/copperexchange/krypton-primitives/pkg/vector_commitments"
)

var _ vc.VectorVerifier[Message, *VectorCommitment, Vector, *Opening] = (*VectorVerifier)(nil)

type VectorVerifier struct {
	sessionId []byte
}

// not UC-secure without session-id.
func NewVectorVerifier(sessionId []byte) *VectorVerifier {
	return &VectorVerifier{
		sessionId: sessionId,
	}
}

func (v *VectorVerifier) Verify(vectorCommitment *VectorCommitment, opening *Opening) error {
	if err := vectorCommitment.Validate(); err != nil {
		return errs.WrapFailed(err, "commitment invalid")
	}
	if err := opening.Validate(); err != nil {
		return errs.WrapFailed(err, "opening invalid")
	}

	localCommitmentValue, err := hashing.Hmac(opening.witness, hashFunc, encodeSessionId(v.sessionId), encode(opening.Message()))
	if err != nil {
		return errs.WrapHashing(err, "could not compute local commitment")
	}
	if !bytes.Equal(localCommitmentValue, vectorCommitment.value) {
		return errs.NewVerification("verification failed")
	}
	return nil
}

func (*VectorVerifier) VerifyAtIndex(index uint, vector Vector, opening commitments.Opening[VectorElement]) error {
	panic("implement me")
}
