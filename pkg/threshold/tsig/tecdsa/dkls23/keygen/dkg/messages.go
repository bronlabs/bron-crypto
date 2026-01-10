package dkg

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
	przsSetup "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs/setup"
)

// Round1Broadcast carries round 1 broadcast messages.
type Round1Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ZeroR1 *przsSetup.Round1Broadcast `cbor:"zeroR1"`
}

// Round1P2P carries round 1 peer-to-peer messages.
type Round1P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	OtR1 *vsot.Round1P2P[P, B, S] `cbor:"otR1"`
}

// Round2P2P carries round 2 peer-to-peer messages.
type Round2P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ZeroR2 *przsSetup.Round2P2P     `cbor:"zeroR2"`
	OtR2   *vsot.Round2P2P[P, B, S] `cbor:"otR2"`
}

// Round3P2P carries round 3 peer-to-peer messages.
type Round3P2P struct {
	OtR3 *vsot.Round3P2P `cbor:"otR3"`
}

// Round4P2P carries round 4 peer-to-peer messages.
type Round4P2P struct {
	OtR4 *vsot.Round4P2P `cbor:"otR4"`
}

// Round5P2P carries round 5 peer-to-peer messages.
type Round5P2P struct {
	OtR5 *vsot.Round5P2P `cbor:"otR5"`
}
