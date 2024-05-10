package hashcomm

import (
	"crypto/subtle"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/comm"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

var _ comm.Verifier[Message, *Commitment, *Opening] = (*Verifier)(nil)

type Verifier struct {
	sessionId []byte
}

func NewVerifier(sessionId []byte) *Verifier {
	return &Verifier{
		sessionId: sessionId,
	}
}

func (v *Verifier) Verify(commitment *Commitment, opening *Opening) error {
	if err := commitment.Validate(); err != nil {
		return errs.WrapValidation(err, "invalid commitment")
	}
	if err := opening.Validate(); err != nil {
		return errs.WrapValidation(err, "invalid opening")
	}
	localCommitment, err := hashing.Hmac(opening.witness, hashFunc, encodeSessionId(v.sessionId), opening.message)
	if err != nil {
		return errs.WrapFailed(err, "could not recompute the commitment")
	}
	if subtle.ConstantTimeCompare(commitment.value, localCommitment) != 1 {
		return errs.NewVerification("verification failed")
	}
	return nil
}
