package signing_helpers

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/hashing"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashmap"
	"github.com/copperexchange/knox-primitives/pkg/sharing/shamir"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/frost"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/frost/signing/aggregation"
)

func ProducePartialSignature(
	participant frost.Participant,
	sessionParticipants []integration.IdentityKey,
	signingKeyShare *frost.SigningKeyShare,
	d_i, e_i curves.Scalar,
	D_alpha, E_alpha *hashmap.HashMap[integration.IdentityKey, curves.Point],
	sharingIdToIdentityKey map[int]integration.IdentityKey,
	identityKeyToSharingId *hashmap.HashMap[integration.IdentityKey, int],
	aggregationParameter *aggregation.SignatureAggregatorParameters,
	message []byte,
) (*frost.PartialSignature, error) {
	cohortConfig := participant.GetCohortConfig()
	mySharingId := participant.GetSharingId()
	R := cohortConfig.CipherSuite.Curve.Point.Identity()
	r_i := cohortConfig.CipherSuite.Curve.Scalar.Zero()

	combinedDsAndEs := []byte{}
	for _, presentParty := range sessionParticipants {
		d_alpha, exists := D_alpha.Get(presentParty)
		if !exists {
			return nil, errs.NewMissing("could not find d_alpha for participant %s", presentParty)
		}
		combinedDsAndEs = append(combinedDsAndEs, d_alpha.ToAffineCompressed()...)
		e_alpha, exists := E_alpha.Get(presentParty)
		if !exists {
			return nil, errs.NewMissing("could not find e_alpha for participant %s", presentParty)
		}
		combinedDsAndEs = append(combinedDsAndEs, e_alpha.ToAffineCompressed()...)
	}

	R_js := hashmap.NewHashMap[integration.IdentityKey, curves.Point]()
	for _, participant := range sessionParticipants {
		sharingId, exists := identityKeyToSharingId.Get(participant)
		if !exists {
			return nil, errs.NewMissing("could not find sharingId for participant %s", participant)
		}
		r_j := cohortConfig.CipherSuite.Curve.Scalar.Hash([]byte{byte(sharingId)}, message, combinedDsAndEs)
		if sharingId == mySharingId {
			r_i = r_j
		}
		D_j, exists := D_alpha.Get(participant)
		if !exists {
			return nil, errs.NewMissing("could not find D_j for j=%d in D_alpha", sharingId)
		}
		E_j, exists := E_alpha.Get(participant)
		if !exists {
			return nil, errs.NewMissing("could not find E_j for j=%d in E_alpha", sharingId)
		}

		R_j := D_j.Add(E_j.Mul(r_j))
		R = R.Add(R_j)
		R_js.Put(participant, R_j)
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
	var exists bool
	for i := 0; i < len(sessionParticipants); i++ {
		presentPartySharingIds[i], exists = identityKeyToSharingId.Get(sessionParticipants[i])
		if !exists {
			return nil, errs.NewMissing("could not find sharingId for participant %s", sessionParticipants[i])
		}
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
