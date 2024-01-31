package noninteractiveSigning

import (
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/signing"
)

func (c *Cosigner) ProducePartialSignature(message []byte) (*dkls24.PartialSignature, error) {
	partialSignature, err := signing.DoRound3Epilogue(
		c,
		c.sessionParticipants,
		message,
		c.preSignature.R,
		c.myShard.SigningKeyShare.Share.Add(c.preSignature.Zeta),
		c.preSignature.Phi,
		c.preSignature.Cu,
		c.preSignature.Cv,
		c.preSignature.Du,
		c.preSignature.Dv,
		c.preSignature.Psi,
		c.preSignature.TheirBigR,
	)
	if err != nil {
		return nil, err //nolint:wrapcheck // done deliberately to forward aborts
	}

	return partialSignature, nil
}
