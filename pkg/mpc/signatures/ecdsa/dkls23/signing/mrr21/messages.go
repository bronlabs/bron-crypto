package signing_mrr21

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/commitments/hashcom"
	rvole_mrr21 "github.com/bronlabs/bron-crypto/pkg/mpc/rvole/mrr21"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23/signing"
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

// Round1P2P carries both rVOLE round-1 messages of a pair: Alice's base-OT
// sender message of the rVOLE in which this party is Alice, and Bob's POPFs
// of the one in which it is Bob.
type Round1P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	MulAliceR1 *rvole_mrr21.AliceRound1P2P[P, B, S] `cbor:"mulAliceR1"`
	MulBobR1   *rvole_mrr21.BobRound1P2P[P, B, S]   `cbor:"mulBobR1"`
}

// Validate checks both messages against the matching rVOLEs: the
// counterparty's Alice message against the rVOLE in which this party is Bob,
// its Bob message against the one in which this party is Alice.
func (m *Round1P2P[P, B, S]) Validate(c *Cosigner[P, B, S], from sharing.ID) error {
	if m == nil || c == nil || m.MulAliceR1 == nil || m.MulBobR1 == nil {
		return ErrValidation.WithMessage("message, cosigner and rVOLE messages must not be nil")
	}
	bob, ok := c.bob[from]
	if !ok {
		return ErrValidation.WithMessage("no rVOLE Bob for party %d", from)
	}
	if err := m.MulAliceR1.Validate(bob, from); err != nil {
		return errs.Wrap(err).WithMessage("invalid rVOLE Alice round 1 message")
	}
	alice, ok := c.alice[from]
	if !ok {
		return ErrValidation.WithMessage("no rVOLE Alice for party %d", from)
	}
	if err := m.MulBobR1.Validate(alice, from); err != nil {
		return errs.Wrap(err).WithMessage("invalid rVOLE Bob round 1 message")
	}
	return nil
}

// Round2Broadcast carries the opening of R_i and the additive public-key share.
type Round2Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigR        P               `cbor:"bigR"`
	BigRWitness hashcom.Witness `cbor:"bigRWitness"`
	Pk          P               `cbor:"pk"`
}

func (m *Round2Broadcast[P, B, S]) opening() *signing.Opening[P, B, S] {
	return &signing.Opening[P, B, S]{BigR: m.BigR, BigRWitness: m.BigRWitness, Pk: m.Pk}
}

// Validate checks that the points are present and in the prime-order group.
func (m *Round2Broadcast[P, B, S]) Validate(_ *Cosigner[P, B, S], _ sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("message must not be nil")
	}
	if err := signing.ValidateOpening(m.opening()); err != nil {
		return errs.Wrap(err).WithMessage("invalid opening")
	}
	return nil
}

// Round2P2P carries Alice's rVOLE message and the check values Γ^u, Γ^v, ψ.
type Round2P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	MulR2  *rvole_mrr21.AliceRound2P2P[P, B, S] `cbor:"mulR2"`
	GammaU P                                    `cbor:"gammaU"`
	GammaV P                                    `cbor:"gammaV"`
	Psi    S                                    `cbor:"psi"`
}

func (m *Round2P2P[P, B, S]) checkValues() *signing.CheckValues[P, B, S] {
	return &signing.CheckValues[P, B, S]{GammaU: m.GammaU, GammaV: m.GammaV, Psi: m.Psi}
}

// Validate checks Alice's message against the rVOLE in which this party is
// Bob, and that the check points are in the prime-order group.
func (m *Round2P2P[P, B, S]) Validate(c *Cosigner[P, B, S], from sharing.ID) error {
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
