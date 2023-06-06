package signing_helpers

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing/aggregation"
	"github.com/copperexchange/crypto-primitives-go/pkg/zkp/schnorr"
	"github.com/pkg/errors"
)

func ProducePartialSignature(
	participant frost.Participant,
	sessionParticipants []integration.IdentityKey,
	signingKeyShare *frost.SigningKeyShare,
	d_i, e_i curves.Scalar,
	D_alpha, E_alpha map[integration.IdentityKey]curves.Point,
	shamirIdToIdentityKey map[int]integration.IdentityKey,
	identityKeyToShamirId map[integration.IdentityKey]int,
	aggregationParameter *aggregation.SignatureAggregatorParameters,
	message []byte,
) (*frost.PartialSignature, error) {
	cohortConfig := participant.GetCohortConfig()
	myShamirId := participant.GetShamirId()
	R := cohortConfig.CipherSuite.Curve.Point.Identity()
	r_i := cohortConfig.CipherSuite.Curve.Scalar.Zero()

	combinedDsAndEs := []byte{}
	for _, presentParty := range sessionParticipants {
		combinedDsAndEs = append(combinedDsAndEs, D_alpha[presentParty].ToAffineCompressed()...)
		combinedDsAndEs = append(combinedDsAndEs, E_alpha[presentParty].ToAffineCompressed()...)
	}

	R_js := map[integration.IdentityKey]curves.Point{}
	for _, participant := range sessionParticipants {
		shamirId := identityKeyToShamirId[participant]
		r_jHashComponents := []byte{byte(shamirId)}
		r_jHashComponents = append(r_jHashComponents, message...)
		r_jHashComponents = append(r_jHashComponents, combinedDsAndEs...)

		r_j := cohortConfig.CipherSuite.Curve.Scalar.Hash(r_jHashComponents)
		if shamirId == myShamirId {
			r_i = r_j
		}
		D_j, exists := D_alpha[participant]
		if !exists {
			return nil, errors.Errorf("%s could not find D_j for j=%d in D_alpha", errs.Missing, shamirId)
		}
		E_j, exists := E_alpha[participant]
		if !exists {
			return nil, errors.Errorf("%s could not find E_j for j=%d in E_alpha", errs.Missing, shamirId)
		}

		R_j := D_j.Add(E_j.Mul(r_j))
		R = R.Add(R_j)
		R_js[participant] = R_j
	}
	if R.IsIdentity() {
		return nil, errors.Errorf("%s R is at infinity", errs.IsIdentity)
	}
	if r_i.IsZero() {
		return nil, errors.Errorf("%s could not find r_i", errs.IsZero)
	}

	c, err := schnorr.ComputeFiatShamirChallege(cohortConfig.CipherSuite, [][]byte{
		R.ToAffineCompressed(), signingKeyShare.PublicKey.ToAffineCompressed(), message,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "%s converting hash to c failed", errs.DeserializationFailed)
	}

	shamir, err := sharing.NewShamir(cohortConfig.Threshold, cohortConfig.TotalParties, cohortConfig.CipherSuite.Curve)
	if err != nil {
		return nil, errors.Wrapf(err, "%s could not initialize shamir methods", errs.Failed)
	}
	presentPartyShamirIds := make([]int, len(sessionParticipants))
	for i := 0; i < len(sessionParticipants); i++ {
		presentPartyShamirIds[i] = identityKeyToShamirId[sessionParticipants[i]]
	}
	lagrangeCoefficients, err := shamir.LagrangeCoeffs(presentPartyShamirIds)
	if err != nil {
		return nil, errors.Wrapf(err, "%s could not derive lagrange coefficients", errs.Failed)
	}

	lambda_i, exists := lagrangeCoefficients[myShamirId]
	if !exists {
		return nil, errors.Errorf("%s could not find my lagrange coefficient", errs.Missing)
	}

	eiri := e_i.Mul(r_i)
	lambda_isic := lambda_i.Mul(signingKeyShare.Share.Mul(c))
	z_i := d_i.Add(eiri.Add(lambda_isic))

	if participant.IsSignatureAggregator() {
		if aggregationParameter == nil {
			return nil, errors.Errorf("%s aggregation parameter is nil when the party is signature aggregator", errs.IsNil)
		}
		aggregationParameter.Z_i = z_i
		aggregationParameter.R = R
		aggregationParameter.R_js = R_js
		aggregationParameter.D_alpha = D_alpha
		aggregationParameter.E_alpha = E_alpha
	}

	return &frost.PartialSignature{
		Zi: z_i,
	}, nil
}
