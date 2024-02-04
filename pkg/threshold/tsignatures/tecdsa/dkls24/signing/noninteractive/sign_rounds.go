package noninteractiveSigning

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/signing"
)

func (c *Cosigner) ProducePartialSignature(message []byte) (*dkls24.PartialSignature, error) {
	myShamirShare := &shamir.Share{
		Id:    c.mySharingId,
		Value: c.myShard.SigningKeyShare.Share,
	}
	myAdditiveShare, err := myShamirShare.ToAdditive(c.sessionShamirIds)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert my shamir share to additive share")
	}
	sk := myAdditiveShare.Add(c.preSignature.Zeta)

	partialSignature, err := signing.DoRound3Epilogue(
		c,
		c.sessionParticipants,
		message,
		c.preSignature.R,
		sk,
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
