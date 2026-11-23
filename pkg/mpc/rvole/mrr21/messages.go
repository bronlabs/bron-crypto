package rvole_mrr21

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/mpc/rvole"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/mrr21"
)

// AliceRound1P2P carries Alice's base-OT sender message m_S.
type AliceRound1P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	OT *mrr21.SenderRound1P2P[Message, P, S] `cbor:"ot"`
}

// Validate checks that the message comes from Bob's counterparty and is a
// valid base-OT sender message.
func (m *AliceRound1P2P[P, B, S]) Validate(bob *Bob[P, B, S], from sharing.ID) error {
	if m == nil || bob == nil || m.OT == nil {
		return rvole.ErrValidation.WithMessage("message, Bob and OT message must not be nil")
	}
	if from != bob.core.CopartyID() {
		return rvole.ErrValidation.WithMessage("message from party %d, expected %d", from, bob.core.CopartyID())
	}
	if err := m.OT.Validate(bob.receiver, from); err != nil {
		return errs.Wrap(err).WithMessage("invalid base-OT message")
	}
	return nil
}

// BobRound1P2P carries Bob's base-OT receiver message, the ξ programmed POPFs.
type BobRound1P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	OT *mrr21.ReceiverRound1P2P[Message, P, S] `cbor:"ot"`
}

// Validate checks that the message comes from Alice's counterparty and is a
// valid base-OT receiver message.
func (m *BobRound1P2P[P, B, S]) Validate(alice *Alice[P, B, S], from sharing.ID) error {
	if m == nil || alice == nil || m.OT == nil {
		return rvole.ErrValidation.WithMessage("message, Alice and OT message must not be nil")
	}
	if from != alice.core.CopartyID() {
		return rvole.ErrValidation.WithMessage("message from party %d, expected %d", from, alice.core.CopartyID())
	}
	if err := m.OT.Validate(alice.sender, from); err != nil {
		return errs.Wrap(err).WithMessage("invalid base-OT message")
	}
	return nil
}

// AliceRound2P2P carries Alice's multiplication message.
type AliceRound2P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Multiply *rvole.MultiplyMessage[P, B, S] `cbor:"multiply"`
}

// Validate checks that the message comes from Bob's counterparty and is well
// formed for the suite.
func (m *AliceRound2P2P[P, B, S]) Validate(bob *Bob[P, B, S], from sharing.ID) error {
	if m == nil || bob == nil {
		return rvole.ErrValidation.WithMessage("message and Bob must not be nil")
	}
	if err := bob.core.ValidateMultiply(m.Multiply, from); err != nil {
		return errs.Wrap(err).WithMessage("invalid multiplication message")
	}
	return nil
}
