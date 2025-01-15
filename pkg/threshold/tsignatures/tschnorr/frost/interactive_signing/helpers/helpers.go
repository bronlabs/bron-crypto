package helpers

import (
	"sort"

	"github.com/bronlabs/krypton-primitives/pkg/base"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/hashing"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/schnorr"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost"
)

func ProducePartialSignature(
	participant types.ThresholdSignatureParticipant,
	protocolConfig types.ThresholdSignatureProtocol,
	quorum ds.Set[types.IdentityKey],
	signingKeyShare *frost.SigningKeyShare,
	d_i, e_i curves.Scalar,
	bigD_alpha, bigE_alpha ds.Map[types.IdentityKey, curves.Point],
	sharingConfig types.SharingConfig,
	message []byte,
) (*frost.PartialSignature, error) {
	R, _, r_js, err := ComputeR(protocolConfig, sharingConfig, quorum, bigD_alpha, bigE_alpha, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute R")
	}
	r_i, exists := r_js.Get(participant.IdentityKey())
	if !exists {
		return nil, errs.NewMissing("could not find my r_j")
	}
	c, err := schnorr.MakeGenericSchnorrChallenge(protocolConfig.SigningSuite(),
		R.ToAffineCompressed(), signingKeyShare.PublicKey.ToAffineCompressed(), message,
	)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "converting hash to c failed")
	}

	presentPartySharingIds := make([]uint, quorum.Size())
	i := 0
	for identityKey := range quorum.Iter() {
		sharingId, exists := sharingConfig.Reverse().Get(identityKey)
		if !exists {
			return nil, errs.NewMissing("could not find sharing id of %s", identityKey.String())
		}
		presentPartySharingIds[i] = uint(sharingId)
		i++
	}
	shamirShare := &shamir.Share{
		Id:    uint(participant.SharingId()),
		Value: signingKeyShare.Share,
	}
	additiveShare, err := shamirShare.ToAdditive(presentPartySharingIds)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not get my additive share")
	}

	eiri := e_i.Mul(r_i)
	lambda_isic := additiveShare.Mul(c)
	z_i := d_i.Add(eiri.Add(lambda_isic))

	return &frost.PartialSignature{
		Zi: z_i,
	}, nil
}

func ComputeR(protocolConfig types.ThresholdSignatureProtocol, sharingConfig types.SharingConfig, quorum ds.Set[types.IdentityKey], bigD_alpha, bigE_alpha ds.Map[types.IdentityKey, curves.Point], message []byte) (bigR curves.Point, bigR_js ds.Map[types.IdentityKey, curves.Point], r_js ds.Map[types.IdentityKey, curves.Scalar], err error) {
	// we need to consistently order the Ds and Es
	combinedDsAndEs := []byte{}
	sortedIdentities := types.ByPublicKey(quorum.List())
	sort.Sort(sortedIdentities)
	for _, presentParty := range sortedIdentities {
		d_j, exists := bigD_alpha.Get(presentParty)
		if !exists {
			return nil, nil, nil, errs.NewMissing("missing d_j for party %s", presentParty.String())
		}
		e_j, exists := bigE_alpha.Get(presentParty)
		if !exists {
			return nil, nil, nil, errs.NewMissing("missing e_j for party %s", presentParty.String())
		}
		combinedDsAndEs = append(combinedDsAndEs, d_j.ToAffineCompressed()...)
		combinedDsAndEs = append(combinedDsAndEs, e_j.ToAffineCompressed()...)
	}

	bigR_js = hashmap.NewHashableHashMap[types.IdentityKey, curves.Point]()
	r_js = hashmap.NewHashableHashMap[types.IdentityKey, curves.Scalar]()
	for identityKey := range quorum.Iter() {
		sharingId, exists := sharingConfig.Reverse().Get(identityKey)
		if !exists {
			return nil, nil, nil, errs.NewMissing("couldn't find the sharing id for participant %s", identityKey.String())
		}
		rjMessage, err := hashing.HashPrefixedLength(base.RandomOracleHashFunction, []byte{byte(sharingId)}, message, combinedDsAndEs)
		if err != nil {
			return nil, nil, nil, errs.WrapHashing(err, "couldn't produce rj message")
		}
		r_j, err := protocolConfig.SigningSuite().Curve().ScalarField().Hash(rjMessage)
		if err != nil {
			return nil, nil, nil, errs.WrapHashing(err, "could not hash to r_j")
		}
		r_js.Put(identityKey, r_j)
		D_j, exists := bigD_alpha.Get(identityKey)
		if !exists {
			return nil, nil, nil, errs.NewMissing("could not find D_j for j=%d in D_alpha", sharingId)
		}
		E_j, exists := bigE_alpha.Get(identityKey)
		if !exists {
			return nil, nil, nil, errs.NewMissing("could not find E_j for j=%d in E_alpha", sharingId)
		}

		bigR_js.Put(identityKey, D_j.Add(E_j.ScalarMul(r_j)))
	}

	bigR = protocolConfig.Curve().AdditiveIdentity()
	for _, rjs := range bigR_js.Values() {
		bigR = bigR.Add(rjs)
	}

	return bigR, bigR_js, r_js, nil
}
