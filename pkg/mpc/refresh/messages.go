package refresh

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/zero/hjky"
)

// Round1Broadcast carries the public commitments for the zero-share offset.
type Round1Broadcast[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	HjkyR1 *hjky.Round1Broadcast[G, S]
}

func (*Round1Broadcast[G, S]) Validate(participant *Participant[G, S]) error {
	return nil
}

// Round1P2P delivers the private zero-share offsets to each participant.
type Round1P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	HjkyR1 *hjky.Round1P2P[G, S]
}

func (*Round1P2P[G, S]) Validate(participant *Participant[G, S]) error {
	return nil
}
