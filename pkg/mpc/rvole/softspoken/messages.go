package rvole_softspoken

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/softspoken"
)

// Round1P2P carries round 1 peer-to-peer messages.
type Round1P2P = softspoken.Round1P2P

// Round2P2P carries round 2 peer-to-peer messages.
type Round2P2P[S algebra.PrimeFieldElement[S]] struct {
	ATilde [][]S
	Eta    []S
	Mu     []byte
}

// Validate validates the message payload.
func (r2 *Round2P2P[S]) Validate(xi, l, rho int) error {
	if r2 == nil {
		return ErrValidation.WithMessage("missing message")
	}
	if len(r2.ATilde) != xi {
		return ErrValidation.WithMessage("invalid message")
	}
	for _, a := range r2.ATilde {
		if len(a) != (l + rho) {
			return ErrValidation.WithMessage("invalid message")
		}
		for _, aa := range a {
			if aa.IsZero() {
				return ErrValidation.WithMessage("invalid message")
			}
		}
	}

	if len(r2.Eta) != rho {
		return ErrValidation.WithMessage("invalid message")
	}
	for _, e := range r2.Eta {
		if e.IsZero() {
			return ErrValidation.WithMessage("invalid message")
		}
	}

	if len(r2.Mu) != (base.CollisionResistanceBytesCeil) {
		return ErrValidation.WithMessage("invalid message")
	}

	return nil
}
