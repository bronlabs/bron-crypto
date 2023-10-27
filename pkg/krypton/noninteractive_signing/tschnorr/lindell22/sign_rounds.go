package lindell22

import (
	"strconv"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/signing"
)

func (c *Cosigner) ProducePartialSignature(message []byte) (partialSignature *lindell22.PartialSignature, err error) {
	bigRSum := c.cohortConfig.CipherSuite.Curve.Point().Identity()
	bigR2Sum := c.cohortConfig.CipherSuite.Curve.Point().Identity()
	for _, identity := range c.sessionParticipants.Iter() {
		bigRSum = bigRSum.Add(c.myPreSignature.BigR[identity.Hash()])
		bigR2Sum = bigR2Sum.Add(c.myPreSignature.BigR2[identity.Hash()])
	}

	delta := c.cohortConfig.CipherSuite.Curve.Scalar().Hash(
		c.myShard.SigningKeyShare.PublicKey.ToAffineCompressed(),
		bigRSum.ToAffineCompressed(),
		bigR2Sum.ToAffineCompressed(),
		[]byte(strconv.Itoa(c.myPreSignatureIndex)),
		message,
	)
	k := c.myPreSignature.K.Add(c.myPreSignature.K2.Mul(delta))
	bigR := bigRSum.Add(bigR2Sum.Mul(delta))

	if c.taproot {
		if bigR.Y().IsOdd() {
			k = k.Neg()
			bigR = bigR.Neg()
		}
	}

	// 3.ii. compute e = H(R || pk || message)
	var e curves.Scalar
	if c.taproot {
		e, err = hashing.CreateDigestScalar(c.cohortConfig.CipherSuite, bigR.ToAffineCompressed()[1:], c.myShard.SigningKeyShare.PublicKey.ToAffineCompressed()[1:], message)
	} else {
		e, err = hashing.CreateDigestScalar(c.cohortConfig.CipherSuite, bigR.ToAffineCompressed(), c.myShard.SigningKeyShare.PublicKey.ToAffineCompressed(), message)
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
