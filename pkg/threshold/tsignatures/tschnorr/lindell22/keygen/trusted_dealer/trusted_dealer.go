package trusted_dealer

import (
	"io"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/trusted_dealer"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
)

func Keygen(protocol types.ThresholdProtocol, prng io.Reader) (ds.Map[types.IdentityKey, *lindell22.Shard], error) {
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not validate cohort config")
	}
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}

	schnorrPrivateKey, err := protocol.Curve().ScalarField().Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not generate random schnorr private key")
	}

	signingKeyShares, partialPublicKeys, err := trusted_dealer.Deal(protocol, schnorrPrivateKey, prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not deal shares")
	}

	shards := hashmap.NewHashableHashMap[types.IdentityKey, *lindell22.Shard]()
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	for pair := range sharingConfig.Iter() {
		identityKey := pair.Value

		sks, exists := signingKeyShares.Get(identityKey)
		if !exists {
			return nil, errs.NewFailed("share is missing")
		}
		ppk, exists := partialPublicKeys.Get(identityKey)
		if !exists {
			return nil, errs.NewFailed("share is missing")
		}

		shards.Put(identityKey, &lindell22.Shard{
			SigningKeyShare: sks,
			PublicKeyShares: ppk,
		})
	}

	return shards, nil
}
