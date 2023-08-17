package signing_helpers

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/hashing"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/sharing/shamir"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/frost"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/frost/signing/aggregation"
)

func ProducePartialSignature(
	participant frost.Participant,
	sessionParticipants []integration.IdentityKey,
	signingKeyShare *frost.SigningKeyShare,
	d_i, e_i curves.Scalar,
	D_alpha, E_alpha map[helper_types.IdentityHash]curves.Point,
	sharingIdToIdentityKey map[int]integration.IdentityKey,
	identityKeyToSharingId map[helper_types.IdentityHash]int,
	aggregationParameter *aggregation.SignatureAggregatorParameters,
	message []byte,
) (*frost.PartialSignature, error) {
	cohortConfig := participant.GetCohortConfig()
	mySharingId := participant.GetSharingId()
	R := cohortConfig.CipherSuite.Curve.Point().Identity()
	r_i := cohortConfig.CipherSuite.Curve.Scalar().Zero()

	combinedDsAndEs := []byte{}
	for _, presentParty := range sessionParticipants {
		combinedDsAndEs = append(combinedDsAndEs, D_alpha[presentParty.Hash()].ToAffineCompressed()...)
		combinedDsAndEs = append(combinedDsAndEs, E_alpha[presentParty.Hash()].ToAffineCompressed()...)
	}

	R_js := map[helper_types.IdentityHash]curves.Point{}
	for _, participant := range sessionParticipants {
		sharingId := identityKeyToSharingId[participant.Hash()]
		r_j := cohortConfig.CipherSuite.Curve.Scalar().Hash([]byte{byte(sharingId)}, message, combinedDsAndEs)
		if sharingId == mySharingId {
			r_i = r_j
		}
		D_j, exists := D_alpha[participant.Hash()]
		if !exists {
			return nil, errs.NewMissing("could not find D_j for j=%d in D_alpha", sharingId)
		}
		E_j, exists := E_alpha[participant.Hash()]
		if !exists {
			return nil, errs.NewMissing("could not find E_j for j=%d in E_alpha", sharingId)
		}

		R_j := D_j.Add(E_j.Mul(r_j))
		R = R.Add(R_j)
		R_js[participant.Hash()] = R_j
	}
	if R.IsIdentity() {
		return nil, errs.NewIsIdentity("R is at infinity")
	}
	if r_i.IsZero() {
		return nil, errs.NewMissing("could not find r_i")
	}

	c, err := hashing.FiatShamir(
		cohortConfig.CipherSuite,
		R.ToAffineCompressed(),
		signingKeyShare.PublicKey.ToAffineCompressed(),
		message,
	)
	if err != nil {
		return nil, errs.WrapDeserializationFailed(err, "converting hash to c failed")
	}

	presentPartySharingIds := make([]int, len(sessionParticipants))
	for i := 0; i < len(sessionParticipants); i++ {
		presentPartySharingIds[i] = identityKeyToSharingId[sessionParticipants[i].Hash()]
	}

	shamirShare := &shamir.Share{
		Id:    participant.GetSharingId(),
		Value: signingKeyShare.Share,
	}
	additiveShare, err := shamirShare.ToAdditive(presentPartySharingIds)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not get my additive share")
	}

	eiri := e_i.Mul(r_i)
	lambda_isic := additiveShare.Mul(c)
	z_i := d_i.Add(eiri.Add(lambda_isic))

	if participant.IsSignatureAggregator() {
		if aggregationParameter == nil {
			return nil, errs.NewIsNil("aggregation parameter is nil when the party is signature aggregator")
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
