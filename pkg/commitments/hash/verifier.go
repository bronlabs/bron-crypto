package hashcommitments

import (
	"crypto/subtle"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

var _ commitments.Verifier[Message, *Commitment, *Opening] = (*Verifier)(nil)

type Verifier struct {
	sessionId []byte
	prefix    []byte
}

func NewVerifier(sessionId []byte, seed ...Message) *Verifier {
	return &Verifier{
		prefix:    encode(seed...),
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
	localCommitment, err := hashing.Hmac(opening.witness, hashFunc, encodeSessionId(v.sessionId), v.prefix, opening.message)
	if err != nil {
		return errs.WrapFailed(err, "could not recompute the commitment")
	}
	if subtle.ConstantTimeCompare(commitment.value, localCommitment) != 1 {
		return errs.NewVerification("verification failed")
	}
	return nil
}
