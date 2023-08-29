package noninteractive

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/hashing"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/signing"
)

func (c *Cosigner) ProducePartialSignature(message []byte) (partialSignature *lindell22.PartialSignature, err error) {
	k := c.myPreSignature.K
	bigRSum := c.cohortConfig.CipherSuite.Curve.Point().Identity()
	for _, identity := range c.sessionParticipants.Iter() {
		bigRSum = bigRSum.Add(c.myPreSignature.BigR[identity.Hash()])
	}
	if c.taproot {
		if bigRSum.Y().IsOdd() {
			k = k.Neg()
			bigRSum = bigRSum.Neg()
		}
	}

	// 3.ii. compute e = H(Rsum || pk || message)
	var e curves.Scalar
	if c.taproot {
		e, err = hashing.CreateDigestScalar(c.cohortConfig.CipherSuite, bigRSum.ToAffineCompressed()[1:], c.myShard.SigningKeyShare.PublicKey.ToAffineCompressed()[1:], message)
	} else {
		e, err = hashing.CreateDigestScalar(c.cohortConfig.CipherSuite, bigRSum.ToAffineCompressed(), c.myShard.SigningKeyShare.PublicKey.ToAffineCompressed(), message)
	}
	if err != nil {
		return nil, errs.NewFailed("cannot create digest scalar")
	}

	// 3.iii. compute additive share d_i' = lambda_i * share
	dPrime, err := signing.ToAdditiveShare(c.myShard.SigningKeyShare.Share, c.mySharingId, c.sessionParticipants, c.identityKeyToSharingId)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot converts to additive share")
	}
	if c.taproot {
		if c.myShard.SigningKeyShare.PublicKey.Y().IsOdd() {
			dPrime = dPrime.Neg()
		}
	}

	// 3.iv. compute s = k + d * e
	s := k.Add(e.Mul(dPrime))

	return &lindell22.PartialSignature{
		R: c.cohortConfig.CipherSuite.Curve.ScalarBaseMult(k),
		S: s,
	}, nil
}
