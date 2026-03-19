package rvole_bbot

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot"
)

// Round1P2P carries round 1 peer-to-peer messages.
type Round1P2P[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]] struct {
	OtR1 *ecbbot.Round1P2P[GE, SE]
}

func (*Round1P2P[GE, SE]) Validate(bob *Bob[GE, SE]) error {
	return nil
}

// Round2P2P carries round 2 peer-to-peer messages.
type Round2P2P[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]] struct {
	OtR2 *ecbbot.Round2P2P[GE, SE]
}

func (*Round2P2P[GE, SE]) Validate(alice *Alice[GE, SE]) error {
	return nil
}

// Round3P2P carries round 3 peer-to-peer messages.
type Round3P2P[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]] struct {
	ATilde [][]SE `cbor:"aTilde"`
	Eta    []SE   `cbor:"eta"`
	Mu     []byte `cbor:"mu"`
}

// Validate validates the message payload dimensions.
func (r3 *Round3P2P[GE, SE]) Validate(bob *Bob[GE, SE]) error {
	xi, l, rho := bob.xi, bob.suite.l, bob.rho
	if r3 == nil {
		return ErrValidation.WithMessage("missing message")
	}
	if len(r3.ATilde) != xi {
		return ErrValidation.WithMessage("invalid ATilde length")
	}
	for _, a := range r3.ATilde {
		if len(a) != (l + rho) {
			return ErrValidation.WithMessage("invalid ATilde row length")
		}
	}
	if len(r3.Eta) != rho {
		return ErrValidation.WithMessage("invalid Eta length")
	}
	if len(r3.Mu) != base.CollisionResistanceBytesCeil {
		return ErrValidation.WithMessage("invalid Mu length")
	}
	return nil
}
