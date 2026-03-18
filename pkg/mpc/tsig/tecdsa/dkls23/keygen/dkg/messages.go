package dkg

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
)

// Round1P2P carries round 1 peer-to-peer messages.
type Round1P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	OtR1 *vsot.Round1P2P[P, B, S] `cbor:"otR1"`
}

func (*Round1P2P[P, B, S]) Validate(*Participant[P, B, S]) error { return nil }

// Round2P2P carries round 2 peer-to-peer messages.
type Round2P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	OtR2 *vsot.Round2P2P[P, B, S] `cbor:"otR2"`
}

func (*Round2P2P[P, B, S]) Validate(*Participant[P, B, S]) error { return nil }

// Round3P2P carries round 3 peer-to-peer messages.
type Round3P2P struct {
	OtR3 *vsot.Round3P2P `cbor:"otR3"`
}

func (*Round3P2P) Validate(any) error { return nil }

// Round4P2P carries round 4 peer-to-peer messages.
type Round4P2P struct {
	OtR4 *vsot.Round4P2P `cbor:"otR4"`
}

func (*Round4P2P) Validate(any) error { return nil }

// Round5P2P carries round 5 peer-to-peer messages.
type Round5P2P struct {
	OtR5 *vsot.Round5P2P `cbor:"otR5"`
}

func (*Round5P2P) Validate(any) error { return nil }
