package rvole_softspoken

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/softspoken"
)

// Round1P2P carries round 1 peer-to-peer messages.
type Round1P2P[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	OtR1 *softspoken.Round1P2P
}

func (m *Round1P2P[P, B, S]) Validate(alice *Alice[P, B, S], from sharing.ID) error {
	if m == nil || m.OtR1 == nil {
		return ErrValidation.WithMessage("missing message")
	}
	if err := m.OtR1.Validate(alice.sender, from); err != nil {
		return errs.Wrap(err).WithMessage("invalid OT round 1 message")
	}

	return nil
}

// Round2P2P carries round 2 peer-to-peer messages.
type Round2P2P[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ATilde [][]S
	Eta    []S
	Mu     []byte
}

// Validate validates the message payload.
func (r2 *Round2P2P[P, B, S]) Validate(bob *Bob[P, B, S], _ sharing.ID) error {
	xi, l, rho := bob.xi, bob.suite.l, bob.rho
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
