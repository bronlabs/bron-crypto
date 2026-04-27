package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/errs-go/errs"
)

// VerifierOption is a functional option for configuring verifiers.
type VerifierOption[E FiniteAbelianGroupElement[E, S], S algebra.RingElement[S]] = func(*Verifier[E, S]) error

// Verifier checks Pedersen commitments against provided messages and witnesses.
type Verifier[E FiniteAbelianGroupElement[E, S], S algebra.RingElement[S]] struct {
	commitments.GenericVerifier[*Committer[E, S], *Witness[S], *Message[S], *Commitment[E, S]]
	witnessRangeCheck func(witness *Witness[S]) error
	messageRangeCheck func(message *Message[S]) error
}

// Verify checks that commitment opens to (message, witness). It first runs the
// scheme's message and witness range checks — for ring-Pedersen these enforce
// the bit-bound and statistical-hiding ranges, while for prime-group schemes
// they reduce to membership in the scalar field — and then recomputes
// g^message · h^witness and compares it with the commitment.
func (v *Verifier[E, S]) Verify(commitment *Commitment[E, S], message *Message[S], witness *Witness[S]) error {
	if err := v.messageRangeCheck(message); err != nil {
		return errs.Wrap(err).WithMessage("invalid message")
	}
	if err := v.witnessRangeCheck(witness); err != nil {
		return errs.Wrap(err).WithMessage("invalid witness")
	}
	err := v.GenericVerifier.Verify(commitment, message, witness)
	if err != nil {
		return errs.Wrap(err).WithMessage("verification failed")
	}
	return nil
}
