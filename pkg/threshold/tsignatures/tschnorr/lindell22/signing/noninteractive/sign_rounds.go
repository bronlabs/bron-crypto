package noninteractive_signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr"
)

func (c *Cosigner[V]) ProducePartialSignature(message []byte) (partialSignature *tschnorr.PartialSignature, err error) {
	bigR1Sum := c.protocol.CipherSuite().Curve().ScalarBaseMult(c.ppm.PrivateMaterial.K1)
	bigR2Sum := c.protocol.CipherSuite().Curve().ScalarBaseMult(c.ppm.PrivateMaterial.K2)
	for identity := range c.quorum.Iter() {
		if identity.Equal(c.IdentityKey()) {
			continue
		}
		thisR1, exists := c.ppm.PreSignature.BigR1.Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find R1 contribution from %s", identity.String())
		}
		thisR2, exists := c.ppm.PreSignature.BigR2.Get(identity)
		if !exists {
			return nil, errs.NewMissing("could not find R2 contribution from %s", identity.String())
		}
		bigR1Sum = bigR1Sum.Add(thisR1)
		bigR2Sum = bigR2Sum.Add(thisR2)
	}

	deltaMessage, err := hashing.HashChain(base.RandomOracleHashFunction,
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

	// 3.ii. compute e = H(R || pk || message)
	eBytes := c.variant.ComputeChallengeBytes(bigR, c.myShard.PublicKey(), message)
	e, err := schnorr.MakeGenericSchnorrChallenge(c.protocol.CipherSuite(), eBytes)
	if err != nil {
		return nil, errs.NewFailed("cannot create digest scalar")
	}

	// 3.iii. compute additive share d_i' = lambda_i * share
	sk, err := c.myShard.SigningKeyShare.ToAdditive(c.IdentityKey(), c.quorum, c.protocol)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot converts to additive share")
	}

	// 3.iv. compute s = k + d * e
	s := c.variant.ComputeResponse(bigR, c.myShard.PublicKey(), k, sk, e)

	return &tschnorr.PartialSignature{
		E: e,
		R: c.variant.ComputeNonceCommitment(bigR, c.protocol.CipherSuite().Curve().ScalarBaseMult(k)),
		S: s,
	}, nil
}
