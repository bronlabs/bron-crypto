package aggregation

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	schnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost/interactive_signing/helpers"
)

func (a *Aggregator) Aggregate(partialSignatures ds.Map[types.IdentityKey, *frost.PartialSignature]) (*schnorr.Signature, error) {
	R, R_js, _, err := helpers.ComputeR(a.Protocol, a.SharingConfig, a.Quorum, a.parameters.D_alpha, a.parameters.E_alpha, a.Message)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute R")
	}

	dealer, err := shamir.NewDealer(a.Protocol.Threshold(), a.Protocol.TotalParties(), a.Protocol.CipherSuite().Curve())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not initialise shamir config")
	}

	sharingIds := make([]uint, a.Quorum.Size())
	i := 0
	for identityKey := range a.Quorum.Iter() {
		sharingId, exists := a.SharingConfig.Reverse().Get(identityKey)
		if !exists {
			return nil, errs.NewMissing("could not find sharign id of %s", identityKey.String())
		}
		sharingIds[i] = uint(sharingId)
		i++
	}
	lagrangeCoefficients, err := dealer.LagrangeCoefficients(sharingIds)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute lagrange coefficients")
	}
	c, err := schnorr.MakeSchnorrCompatibleChallenge(a.Protocol.CipherSuite(),
		R.ToAffineCompressed(), a.PublicKey.ToAffineCompressed(), a.Message,
	)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "converting hash to c failed")
	}

	for jIdentityKey := range a.Quorum.Iter() {
		j, exists := a.SharingConfig.Reverse().Get(jIdentityKey)
		if !exists {
			return nil, errs.NewMissing("could not find the identity key of cosigner with sharing id %d", j)
		}
		Y_j, exists := a.PublicKeyShares.Shares.Get(jIdentityKey)
		if !exists {
			return nil, errs.NewMissing("could not find public key share of sharing id %d", j)
		}
		lambda_j, exists := lagrangeCoefficients[uint(j)]
		if !exists {
			return nil, errs.NewMissing("could not find lagrange coefficient of sharing id %d", j)
		}

		partialSignature, exists := partialSignatures.Get(jIdentityKey)
		if !exists {
			return nil, errs.NewMissing("could not find partial signature from sharing id %d", j)
		}

		R_j, exists := R_js.Get(jIdentityKey)
		if !exists {
			return nil, errs.NewMissing("could not find R_j for j=%d", j)
		}

		z_jG := a.Protocol.CipherSuite().Curve().ScalarBaseMult(partialSignature.Zi)
		cLambda_jY_j := Y_j.Mul(c.Mul(lambda_j))
		rhs := R_j.Add(cLambda_jY_j)

		if !z_jG.Equal(rhs) {
			return nil, errs.NewIdentifiableAbort(j, "participant with sharing id is misbehaving")
		}
	}

	s := a.Protocol.CipherSuite().Curve().ScalarField().Zero()
	for pair := range partialSignatures.Iter() {
		partialSignature := pair.Value
		s = s.Add(partialSignature.Zi)
	}

	sigma := &schnorr.Signature{R: R, S: s}

	if err := schnorr.Verify(a.Protocol.CipherSuite(), &schnorr.PublicKey{A: a.PublicKey}, a.Message, sigma); err != nil {
		return nil, errs.WrapVerification(err, "could not verify frost signature")
	}
	return sigma, nil
}
