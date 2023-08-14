package noninteractive

import (
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/hashing"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/signing"
)

func (c *Cosigner) ProducePartialSignature(message []byte) (partialSignature *lindell22.PartialSignature, err error) {
	k := c.myPreSignature.K
	bigRSum := c.cohortConfig.CipherSuite.Curve.Point().Identity()
	for _, identity := range c.sessionParticipants {
		bigRSum = bigRSum.Add(c.myPreSignature.BigR[identity])
	}

	// 3.ii. compute e = H(Rsum || pk || || message)
	eBytes, err := hashing.Hash(c.cohortConfig.CipherSuite.Hash, bigRSum.ToAffineCompressed(), c.myShard.SigningKeyShare.PublicKey.ToAffineCompressed(), message)
	if err != nil {
		return nil, errs.NewFailed("cannot create message digest")
	}
	e, err := c.cohortConfig.CipherSuite.Curve.Scalar().SetBytesWide(eBytes)
	if err != nil {
		return nil, errs.NewFailed("cannot set scalar")
	}

	// 3.iii. compute additive share d_i' = lambda_i * share
	dPrime, err := signing.ToAdditiveShare(c.myShard.SigningKeyShare.Share, c.mySharingId, c.sessionParticipants, c.identityKeyToSharingId)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot converts to additive share")
	}

	// 3.iv. compute s = k + d * e
	s := k.Add(e.Mul(dPrime))

	return &lindell22.PartialSignature{
		R: c.cohortConfig.CipherSuite.Curve.ScalarBaseMult(k),
		S: s,
	}, nil
}
