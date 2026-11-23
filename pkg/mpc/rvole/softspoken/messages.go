package rvole_softspoken

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/mpc/rvole"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/softspoken"
)

// Round1P2P is Bob's only message: the random OT extension for ξ OTs.
type Round1P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	OT *softspoken.RoundExtendP2P `cbor:"ot"`
}

// Validate checks that the message comes from Alice's counterparty and that
// its extension is valid and sized for exactly ξ OTs.
func (m *Round1P2P[P, B, S]) Validate(alice *Alice[P, B, S], from sharing.ID) error {
	if m == nil || alice == nil || m.OT == nil {
		return rvole.ErrValidation.WithMessage("message, Alice and OT extension must not be nil")
	}
	if from != alice.core.CopartyID() {
		return rvole.ErrValidation.WithMessage("message from party %d, expected %d", from, alice.core.CopartyID())
	}
	if err := m.OT.Validate(alice.sender, from); err != nil {
		return errs.Wrap(err).WithMessage("invalid OT extension")
	}
	if l, xi := len(m.OT.COTEMessage.U[0])*8-sigma, alice.core.Suite().Xi(); l != xi {
		return rvole.ErrValidation.WithMessage("extension of %d OTs, expected %d", l, xi)
	}
	return nil
}

// Round2P2P is Alice's only message: the masked rows and the check.
type Round2P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Multiply *rvole.MultiplyMessage[P, B, S] `cbor:"multiply"`
}

// Validate checks that the message comes from Bob's counterparty and is well
// formed for the suite.
func (m *Round2P2P[P, B, S]) Validate(bob *Bob[P, B, S], from sharing.ID) error {
	if m == nil || bob == nil {
		return rvole.ErrValidation.WithMessage("message and Bob must not be nil")
	}
	if err := bob.core.ValidateMultiply(m.Multiply, from); err != nil {
		return errs.Wrap(err).WithMessage("invalid multiplication message")
	}
	return nil
}
