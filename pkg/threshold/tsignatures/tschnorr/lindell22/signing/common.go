package signing

import (
	"sort"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	schnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
)

func ToAdditiveShare(shamirShare curves.Scalar, mySharingId int, participants *hashset.HashSet[integration.IdentityKey], identityKeyToSharingId map[types.IdentityHash]int) (curves.Scalar, error) {
	shamirIndices := make([]int, participants.Len())
	i := -1
	for _, identity := range participants.Iter() {
		i++
		shamirIndices[i] = identityKeyToSharingId[identity.Hash()]
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

func BigS(participants *hashset.HashSet[integration.IdentityKey]) []byte {
	sortedIdentities := integration.ByPublicKey(participants.List())
	sort.Sort(sortedIdentities)
	var bigS []byte
	for _, identity := range sortedIdentities {
		pid := identity.PublicKey().ToAffineCompressed()
		bigS = append(bigS, pid...)
	}

	return bigS
}

func Aggregate(partialSignatures ...*lindell22.PartialSignature) (signature *schnorr.Signature, err error) {
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
	return &schnorr.Signature{
		R: r,
		S: s,
	}, nil
}
