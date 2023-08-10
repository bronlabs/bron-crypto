package signing

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashmap"
	"github.com/copperexchange/knox-primitives/pkg/sharing/shamir"
	"github.com/copperexchange/knox-primitives/pkg/signatures/eddsa"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22"
)

func ToAdditiveShare(shamirShare curves.Scalar, mySharingId int, participants []integration.IdentityKey, identityKeyToSharingId *hashmap.HashMap[integration.IdentityKey, int]) (curves.Scalar, error) {
	shamirIndices := make([]int, len(participants))
	var exists bool
	for i, identity := range participants {
		shamirIndices[i], exists = identityKeyToSharingId.Get(identity)
		if !exists {
			return nil, errs.NewFailed("identity not found")
		}
	}
	share := &shamir.Share{
		Id:    mySharingId,
		Value: shamirShare,
	}
	additiveShare, err := share.ToAdditive(shamirIndices)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot convert to additive share")
	}

	return additiveShare, nil
}

func BigS(participants []integration.IdentityKey) []byte {
	sortedIdentities := integration.SortIdentityKeys(participants)
	var bigS []byte
	for _, identity := range sortedIdentities {
		pid := identity.PublicKey().ToAffineCompressed()
		bigS = append(bigS, pid...)
	}

	return bigS
}

func Aggregate(partialSignatures ...*lindell22.PartialSignature) (signature *eddsa.Signature, err error) {
	if len(partialSignatures) < 2 {
		return nil, errs.NewFailed("not enough partial signatures")
	}

	r := partialSignatures[0].R.Identity()
	s := partialSignatures[0].S.Zero()
	for _, partialSignature := range partialSignatures {
		// compute Rsum
		r = r.Add(partialSignature.R)

		// compute Ssum
		s = s.Add(partialSignature.S)
	}

	// return (Rsum, Ssum) as signature
	return &eddsa.Signature{
		R: r,
		Z: s,
	}, nil
}
