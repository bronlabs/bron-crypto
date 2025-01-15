package hashcommitments

import (
	"crypto/subtle"
	"slices"

	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/commitments"
	"github.com/bronlabs/krypton-primitives/pkg/hashing"
)

var _ commitments.Verifier[Message, *Commitment, *Opening] = (*Verifier)(nil)

type Verifier struct {
	sessionId []byte
	prefix    []byte
}

func NewVerifier(sessionId []byte, prefix ...Message) *Verifier {
	return &Verifier{
		prefix:    slices.Concat(prefix...),
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

	localCommitment, err := hashing.KmacPrefixedLength(opening.Witness, nil, sha3.NewCShake128, encodeSessionId(v.sessionId), v.prefix, opening.Message)
	if err != nil {
		return errs.WrapFailed(err, "could not recompute the commitment")
	}

	if subtle.ConstantTimeCompare(commitment.Value, localCommitment) != 1 {
		return errs.NewVerification("verification failed")
	}
	return nil
}
