package signing_softspoken

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/commitments/hashcom"
	rvole_softspoken "github.com/bronlabs/bron-crypto/pkg/mpc/rvole/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23/signing"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/mrr21"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/iknp03"
)

// Round1Broadcast carries the commitment to R_i.
type Round1Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigRCommitment hashcom.Commitment `cbor:"bigRCommitment"`
}

// Validate checks that the commitment is present.
func (m *Round1Broadcast[P, B, S]) Validate(_ *Cosigner[P, B, S], _ sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("message must not be nil")
	}
	if err := signing.ValidateCommitment(m.BigRCommitment); err != nil {
		return errs.Wrap(err).WithMessage("invalid commitment")
	}
	return nil
}

// Round1P2P carries both base-OT messages of a pair: the one this party sends
// as base-OT sender (it is Bob of that rVOLE) and the one it sends as base-OT
// receiver (it is Alice of that rVOLE).
type Round1P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BaseOTSender   *mrr21.SenderRound1P2P[iknp03.Seed, P, S]   `cbor:"baseOTSender"`
	BaseOTReceiver *mrr21.ReceiverRound1P2P[iknp03.Seed, P, S] `cbor:"baseOTReceiver"`
}

// Validate checks both base-OT messages against the matching pairwise
// participants: the counterparty's sender message is for the session in which
// this party is Alice, its receiver message for the one in which it is Bob.
func (m *Round1P2P[P, B, S]) Validate(c *Cosigner[P, B, S], from sharing.ID) error {
	if m == nil || c == nil || m.BaseOTSender == nil || m.BaseOTReceiver == nil {
		return ErrValidation.WithMessage("message, cosigner and base-OT messages must not be nil")
	}
	receiver, ok := c.baseOTReceivers[from]
	if !ok {
		return ErrValidation.WithMessage("no base-OT receiver for party %d", from)
	}
	if err := m.BaseOTSender.Validate(receiver, from); err != nil {
		return errs.Wrap(err).WithMessage("invalid base-OT sender message")
	}
	sender, ok := c.baseOTSenders[from]
	if !ok {
		return ErrValidation.WithMessage("no base-OT sender for party %d", from)
	}
	if err := m.BaseOTReceiver.Validate(sender, from); err != nil {
		return errs.Wrap(err).WithMessage("invalid base-OT receiver message")
	}
	return nil
}

// Round2P2P carries Bob's rVOLE message.
type Round2P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	MulR1 *rvole_softspoken.Round1P2P[P, B, S] `cbor:"mulR1"`
}

// Validate checks Bob's message against the rVOLE in which this party is Alice.
func (m *Round2P2P[P, B, S]) Validate(c *Cosigner[P, B, S], from sharing.ID) error {
	if m == nil || c == nil || m.MulR1 == nil {
		return ErrValidation.WithMessage("message, cosigner and rVOLE message must not be nil")
	}
	alice, ok := c.alice[from]
	if !ok {
		return ErrValidation.WithMessage("no rVOLE Alice for party %d", from)
	}
	if err := m.MulR1.Validate(alice, from); err != nil {
		return errs.Wrap(err).WithMessage("invalid rVOLE round 1 message")
	}
	return nil
}

// Round3Broadcast carries the opening of R_i and the additive public-key share.
type Round3Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigR        P               `cbor:"bigR"`
	BigRWitness hashcom.Witness `cbor:"bigRWitness"`
	Pk          P               `cbor:"pk"`
}

func (m *Round3Broadcast[P, B, S]) opening() *signing.Opening[P, B, S] {
	return &signing.Opening[P, B, S]{BigR: m.BigR, BigRWitness: m.BigRWitness, Pk: m.Pk}
}

// Validate checks that the points are present and in the prime-order group.
func (m *Round3Broadcast[P, B, S]) Validate(_ *Cosigner[P, B, S], _ sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("message must not be nil")
	}
	if err := signing.ValidateOpening(m.opening()); err != nil {
		return errs.Wrap(err).WithMessage("invalid opening")
	}
	return nil
}

// Round3P2P carries Alice's rVOLE message and the check values Γ^u, Γ^v, ψ.
type Round3P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	MulR2  *rvole_softspoken.Round2P2P[P, B, S] `cbor:"mulR2"`
	GammaU P                                    `cbor:"gammaU"`
	GammaV P                                    `cbor:"gammaV"`
	Psi    S                                    `cbor:"psi"`
}

func (m *Round3P2P[P, B, S]) checkValues() *signing.CheckValues[P, B, S] {
	return &signing.CheckValues[P, B, S]{GammaU: m.GammaU, GammaV: m.GammaV, Psi: m.Psi}
}

// Validate checks Alice's message against the rVOLE in which this party is
// Bob, and that the check points are in the prime-order group.
func (m *Round3P2P[P, B, S]) Validate(c *Cosigner[P, B, S], from sharing.ID) error {
	if m == nil || c == nil || m.MulR2 == nil {
		return ErrValidation.WithMessage("message, cosigner and rVOLE message must not be nil")
	}
	bob, ok := c.bob[from]
	if !ok {
		return ErrValidation.WithMessage("no rVOLE Bob for party %d", from)
	}
	if err := m.MulR2.Validate(bob, from); err != nil {
		return errs.Wrap(err).WithMessage("invalid rVOLE round 2 message")
	}
	if err := signing.ValidateCheckValues(m.checkValues()); err != nil {
		return errs.Wrap(err).WithMessage("invalid check values")
	}
	return nil
}
