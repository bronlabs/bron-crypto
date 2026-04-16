package nthroot

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

// Verify wraps the embedded Maurer09 verification to surface errs-style errors.
func (p *Protocol[A]) Verify(statement *Statement[A], commitment *Commitment[A], challengeBytes sigma.ChallengeBytes, response *Response[A]) error {
	if err := p.Protocol.Verify(statement, commitment, challengeBytes, response); err != nil {
		return errs.Join(ErrVerificationFailed.WithStackFrame(), errs.Wrap(err).WithMessage("verification failed"))
	}
	return nil
}
