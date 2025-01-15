package hashvectorcommitments

import (
	"bytes"

	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/commitments"
	"github.com/bronlabs/krypton-primitives/pkg/hashing"
	vc "github.com/bronlabs/krypton-primitives/pkg/vector_commitments"
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

	localCommitment, err := hashing.KmacPrefixedLength(opening.witness, nil, sha3.NewCShake128, encodeSessionId(v.sessionId), encode(opening.GetMessage()))
	if err != nil {
		return errs.WrapFailed(err, "could not recompute the commitment")
	}

	if !bytes.Equal(localCommitment, vectorCommitment.value) {
		return errs.NewVerification("verification failed")
	}
	return nil
}

func (*VectorVerifier) VerifyAtIndex(index uint, vector Vector, opening commitments.Opening[VectorElement]) error {
	panic("implement me")
}
