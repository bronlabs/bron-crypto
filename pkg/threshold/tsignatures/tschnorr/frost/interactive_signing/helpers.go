package interactive_signing

import (
	"sort"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost/interactive_signing/aggregation"
)

func ProducePartialSignature(
	participant frost.Participant,
	sessionParticipants *hashset.HashSet[integration.IdentityKey],
	signingKeyShare *frost.SigningKeyShare,
	d_i, e_i curves.Scalar,
	D_alpha, E_alpha map[types.IdentityHash]curves.Point,
	sharingIdToIdentityKey map[int]integration.IdentityKey,
	identityKeyToSharingId map[types.IdentityHash]int,
	aggregationParameter *aggregation.SignatureAggregatorParameters,
	message []byte,
) (*frost.PartialSignature, error) {
	cohortConfig := participant.GetCohortConfig()
	mySharingId := participant.GetSharingId()
	R := cohortConfig.CipherSuite.Curve.Point().Identity()
	r_i := cohortConfig.CipherSuite.Curve.Scalar().Zero()

	// we need to consistently order the Ds and Es
	combinedDsAndEs := []byte{}
	sortedIdentities := integration.ByPublicKey(sessionParticipants.List())
	sort.Sort(sortedIdentities)
	for _, presentParty := range sortedIdentities {
		combinedDsAndEs = append(combinedDsAndEs, D_alpha[presentParty.Hash()].ToAffineCompressed()...)
		combinedDsAndEs = append(combinedDsAndEs, E_alpha[presentParty.Hash()].ToAffineCompressed()...)
	}

	R_js := map[types.IdentityHash]curves.Point{}
	for _, participant := range sessionParticipants.Iter() {
		sharingId := identityKeyToSharingId[participant.Hash()]
		r_j, err := cohortConfig.CipherSuite.Curve.Scalar().Hash([]byte{byte(sharingId)}, message, combinedDsAndEs)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not hash to r_j")
		}
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

	c, err := hashing.HashToSchnorrScalar(
		cohortConfig.CipherSuite,
		R.ToAffineCompressed(),
		signingKeyShare.PublicKey.ToAffineCompressed(),
		message,
	)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "converting hash to c failed")
	}

	presentPartySharingIds := make([]int, sessionParticipants.Len())
	i := -1
	for _, sessionParticipant := range sessionParticipants.Iter() {
		i++
		presentPartySharingIds[i] = identityKeyToSharingId[sessionParticipant.Hash()]
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
