package trusted_dealer

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/trusted_dealer"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02"
)

func Keygen[K bls.KeySubGroup](protocol types.ThresholdProtocol, prng io.Reader) (ds.Map[types.IdentityKey, *boldyreva02.Shard[K]], error) {
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not validate protocol config")
	}

	subGroup := bls12381.GetSourceSubGroup[K]()

	if protocol.Curve().Name() != subGroup.Name() {
		return nil, errs.NewCurve(
			"protocol's subgroup (%s) is not the same the generic type (%s)",
			protocol.Curve().Name(),
			subGroup.Name(),
		)
	}

	if prng == nil {
		return nil, errs.NewArgument("prng is nil")
	}

	privateKey, err := bls.KeyGen[K](prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to do keygen")
	}

	signingKeyShares, partialPublicKeys, err := trusted_dealer.Deal(protocol, privateKey.D(), prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot deal shares")
	}

	shards := hashmap.NewHashableHashMap[types.IdentityKey, *boldyreva02.Shard[K]]()
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	for _, identityKey := range sharingConfig.Iter() {
		sks, exists := signingKeyShares.Get(identityKey)
		if !exists {
			return nil, errs.NewFailed("share is missing")
		}
		ppk, exists := partialPublicKeys.Get(identityKey)
		if !exists {
			return nil, errs.NewFailed("share is missing")
		}

		shards.Put(identityKey, &boldyreva02.Shard[K]{
			SigningKeyShare: &boldyreva02.SigningKeyShare[K]{
				Share: sks.Share,
				PublicKey: &bls.PublicKey[K]{
					Y: sks.PublicKey.(curves.PairingPoint),
				},
			},
			PublicKeyShares: &boldyreva02.PartialPublicKeys[K]{
				PublicKey: &bls.PublicKey[K]{
					Y: ppk.PublicKey.(curves.PairingPoint),
				},
				Shares:                  ppk.Shares,
				FeldmanCommitmentVector: ppk.FeldmanCommitmentVector,
			},
		})
	}

	return shards, nil
}
