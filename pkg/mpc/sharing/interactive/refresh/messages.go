package refresh

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/interactive/zero/hjky"
)

// Round1Broadcast carries the public commitments for the zero-share offset.
type Round1Broadcast[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] = hjky.Round1Broadcast[G, S]

// Round1P2P delivers the private zero-share offsets to each participant.
type Round1P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] = hjky.Round1P2P[G, S]
