package refresh

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/zero/hjky"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

// Round1Broadcast carries the public commitments for the zero-share offset.
type Round1Broadcast[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	HjkyR1 *hjky.Round1Broadcast[G, S]
}

func (m *Round1Broadcast[G, S]) Validate(participant *Participant[G, S], from sharing.ID) error {
	if m.HjkyR1 == nil {
		return network.ErrInvalidMessage.WithMessage("missing HJKY round 1 broadcast")
	}
	if err := m.HjkyR1.Validate(participant.zeroParticipant, from); err != nil {
		return errs.Wrap(err).WithMessage("invalid HJKY round 1 broadcast")
	}
	return nil
}

// Round1P2P delivers the private zero-share offsets to each participant.
type Round1P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	HjkyR1 *hjky.Round1P2P[G, S]
}

func (m *Round1P2P[G, S]) Validate(participant *Participant[G, S], from sharing.ID) error {
	if m.HjkyR1 == nil {
		return network.ErrInvalidMessage.WithMessage("missing HJKY round 1 unicast")
	}
	if err := m.HjkyR1.Validate(participant.zeroParticipant, from); err != nil {
		return errs.Wrap(err).WithMessage("invalid HJKY round 1 unicast")
	}
	return nil
}
