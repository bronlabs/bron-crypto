package noninteractive_signing

import (
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	schnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
)

func (c *Cosigner) ProducePartialSignature(message []byte) (partialSignature *lindell22.PartialSignature, err error) {
	bigR1Sum := c.protocol.CipherSuite().Curve().ScalarBaseMult(c.ppm.PrivateMaterial.K1)
	bigR2Sum := c.protocol.CipherSuite().Curve().ScalarBaseMult(c.ppm.PrivateMaterial.K2)
	for identity := range c.ppm.PreSigners.Iter() {
		if identity.Equal(c.IdentityKey()) {
			continue
		}
		thisR1, exists := c.ppm.PreSignature.BigR1.Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find R1 contribution from %x", identity.PublicKey())
		}
		thisR2, exists := c.ppm.PreSignature.BigR2.Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find R2 contribution from %x", identity.PublicKey())
		}
		bigR1Sum = bigR1Sum.Add(thisR1)
		bigR2Sum = bigR2Sum.Add(thisR2)
	}

	deltaMessage, err := hashing.HashChain(sha3.New256,
		c.myShard.SigningKeyShare.PublicKey.ToAffineCompressed(),
		bigR1Sum.ToAffineCompressed(),
		bigR2Sum.ToAffineCompressed(),
		message,
	)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't produce delta message")
	}

	delta, err := c.protocol.CipherSuite().Curve().ScalarField().Hash(deltaMessage)
	if err != nil {
		return nil, errs.WrapHashing(err, "cannot hash to scalar")
	}

	k := c.ppm.PrivateMaterial.K1.Add(c.ppm.PrivateMaterial.K2.Mul(delta))
	bigR := bigR1Sum.Add(bigR2Sum.Mul(delta))

	if c.taproot {
		if bigR.AffineY().IsOdd() {
			k = k.Neg()
			bigR = bigR.Neg()
		}
	}

	// 3.ii. compute e = H(R || pk || message)
	var e curves.Scalar
	if c.taproot {
		e, err = schnorr.MakeSchnorrCompatibleChallenge(c.protocol.CipherSuite(), bigR.ToAffineCompressed()[1:], c.myShard.PublicKey().ToAffineCompressed()[1:], message)
	} else {
		e, err = schnorr.MakeSchnorrCompatibleChallenge(c.protocol.CipherSuite(), bigR.ToAffineCompressed(), c.myShard.PublicKey().ToAffineCompressed(), message)
	}
	if err != nil {
		return nil, errs.NewFailed("cannot create digest scalar")
	}

	// 3.iii. compute additive share d_i' = lambda_i * share
	dPrime, err := c.myShard.SigningKeyShare.ToAdditive(c.IdentityKey(), c.ppm.PreSigners, c.protocol)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot converts to additive share")
	}
	if c.taproot {
		if c.myShard.SigningKeyShare.PublicKey.AffineY().IsOdd() {
			dPrime = dPrime.Neg()
		}
	}

	zeroS, err := c.przsSampleParticipant.Sample()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot sample zero share")
	}

	// 3.iv. compute s = k + d * e
	s := k.Add(e.Mul(dPrime)).Add(zeroS)

	return &lindell22.PartialSignature{
		R: c.protocol.CipherSuite().Curve().ScalarBaseMult(k),
		S: s,
	}, nil
}
