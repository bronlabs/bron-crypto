package trusted_dealer

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02"
)

func Keygen[K bls.KeySubGroup](protocol types.ThresholdProtocol, prng io.Reader) (ds.HashMap[types.IdentityKey, *boldyreva02.Shard[K]], error) {
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not validate protocol config")
	}

	subGroup := bls12381.GetSourceSubGroup[K]()

	if protocol.Curve().Name() != subGroup.Name() {
		return nil, errs.NewCurve(
			"cohort's subgroup (%s) is not the same the generic type (%s)",
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

	dealer, err := shamir.NewDealer(protocol.Threshold(), uint(protocol.Participants().Size()), subGroup)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct feldman dealer")
	}

	shamirShares, err := dealer.Split(privateKey.D(), prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to deal the secret")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())

	publicKeySharesMap := hashmap.NewHashableHashMap[types.IdentityKey, curves.Point]()
	for pair := range sharingConfig.Iter() {
		sharingId := pair.Left
		identityKey := pair.Right
		share := subGroup.ScalarBaseMult(shamirShares[sharingId-1].Value)
		publicKeySharesMap.Put(identityKey, share)
	}
	// TODO: fix this
	feldmanCommitmentVector := make([]curves.Point, protocol.Threshold())
	for i := range feldmanCommitmentVector {
		feldmanCommitmentVector[i] = protocol.Curve().Generator()
	}

	shards := hashmap.NewHashableHashMap[types.IdentityKey, *boldyreva02.Shard[K]]()
	for pair := range sharingConfig.Iter() {
		sharingId := pair.Left
		identityKey := pair.Right
		share := shamirShares[sharingId-1].Value
		shards.Put(identityKey, &boldyreva02.Shard[K]{
			SigningKeyShare: &boldyreva02.SigningKeyShare[K]{
				Share:     share,
				PublicKey: privateKey.PublicKey,
			},
			PublicKeyShares: &boldyreva02.PartialPublicKeys[K]{
				PublicKey:               privateKey.PublicKey,
				Shares:                  publicKeySharesMap,
				FeldmanCommitmentVector: feldmanCommitmentVector,
			},
		})
	}

	return shards, nil
}
