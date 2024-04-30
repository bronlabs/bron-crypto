package aggregation

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
	vanillaSchnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost/interactive_signing/helpers"
)

func (a *Aggregator) Aggregate(partialSignatures ds.Map[types.IdentityKey, *frost.PartialSignature]) (*vanillaSchnorr.Signature, error) {
	R, R_js, _, err := helpers.ComputeR(a.Protocol, a.SharingConfig, a.Quorum, a.parameters.D_alpha, a.parameters.E_alpha, a.Message)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute R")
	}

	dealer, err := shamir.NewDealer(a.Protocol.Threshold(), a.Protocol.TotalParties(), a.Protocol.SigningSuite().Curve())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not initialise shamir config")
	}

	sharingIds := make([]uint, a.Quorum.Size())
	i := 0
	for identityKey := range a.Quorum.Iter() {
		sharingId, exists := a.SharingConfig.Reverse().Get(identityKey)
		if !exists {
			return nil, errs.NewMissing("could not find sharing id of %s", identityKey.String())
		}
		sharingIds[i] = uint(sharingId)
		i++
	}
	lagrangeCoefficients, err := dealer.LagrangeCoefficients(sharingIds)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute lagrange coefficients")
	}
	c, err := schnorr.MakeGenericSchnorrChallenge(a.Protocol.SigningSuite(),
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

		z_jG := a.Protocol.SigningSuite().Curve().ScalarBaseMult(partialSignature.Zi)
		cLambda_jY_j := Y_j.ScalarMul(c.Mul(lambda_j))
		rhs := R_j.Add(cLambda_jY_j)

		if !z_jG.Equal(rhs) {
			return nil, errs.NewIdentifiableAbort(j, "participant with sharing id is misbehaving")
		}
	}

	s := a.Protocol.SigningSuite().Curve().ScalarField().Zero()
	for pair := range partialSignatures.Iter() {
		partialSignature := pair.Value
		s = s.Add(partialSignature.Zi)
	}

	sigma := &vanillaSchnorr.Signature{R: R, S: s}

	if err := vanillaSchnorr.Verify(a.Protocol.SigningSuite(), &vanillaSchnorr.PublicKey{A: a.PublicKey}, a.Message, sigma); err != nil {
		return nil, errs.WrapVerification(err, "could not verify frost signature")
	}
	return sigma, nil
}
