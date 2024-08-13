package noninteractive_signing

import (
	"encoding/json"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr"
)

func (c *Cosigner[V, M]) ProducePartialSignature(message M) (partialSignature *tschnorr.PartialSignature, err error) {
	bigR1Sum := c.Protocol.SigningSuite().Curve().ScalarBaseMult(c.ppm.PrivateMaterial.K1)
	bigR2Sum := c.Protocol.SigningSuite().Curve().ScalarBaseMult(c.ppm.PrivateMaterial.K2)
	for iterator := c.quorum.Iterator(); iterator.HasNext(); {
		identity := iterator.Next()
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

	// TODO: come up with something better?
	buf, err := json.Marshal(message)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "couldn't serialise message")
	}

	deltaMessage := hashing.HashPrefixedLength(base.RandomOracleHashFunction,
		c.myShard.SigningKeyShare.PublicKey.ToAffineCompressed(),
		bigR1Sum.ToAffineCompressed(),
		bigR2Sum.ToAffineCompressed(),
		buf,
	)

	delta, err := c.Protocol.SigningSuite().Curve().ScalarField().Hash(deltaMessage)
	if err != nil {
		return nil, errs.WrapHashing(err, "cannot hash to scalar")
	}

	k := c.ppm.PrivateMaterial.K1.Add(c.ppm.PrivateMaterial.K2.Mul(delta))
	bigR := bigR1Sum.Add(bigR2Sum.ScalarMul(delta))

	// 3.ii. compute e = H(R || pk || message)
	e, err := c.variant.ComputeChallenge(c.Protocol.SigningSuite(), bigR, c.myShard.PublicKey(), message)
	if err != nil {
		return nil, errs.NewFailed("cannot create digest scalar")
	}

	// 3.iii. compute additive share d_i' = lambda_i * share
	sk, err := c.myShard.SigningKeyShare.ToAdditive(c.IdentityKey(), c.quorum, c.Protocol)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot converts to additive share")
	}

	// 3.iv. compute s = k + d * e
	s := c.variant.ComputeResponse(bigR, c.myShard.PublicKey(), k, sk, e)

	return &tschnorr.PartialSignature{
		E: e,
		R: c.variant.ComputeNonceCommitment(bigR, c.Protocol.SigningSuite().Curve().ScalarBaseMult(k)),
		S: s,
	}, nil
}
