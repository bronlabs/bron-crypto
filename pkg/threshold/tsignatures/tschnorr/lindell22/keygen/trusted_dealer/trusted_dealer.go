package trusted_dealer

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"io"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/threshold/trusted_dealer"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr/lindell22"
)

func Keygen(protocol types.ThresholdProtocol, prng io.Reader) (ds.Map[types.IdentityKey, *lindell22.Shard], error) {
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not validate protocol config")
	}

	schnorrPrivateKey, err := protocol.Curve().ScalarField().Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not generate random schnorr private key")
	}
	return Deal(protocol, schnorrPrivateKey, prng)
}

func Deal(protocol types.ThresholdProtocol, secret curves.Scalar, prng io.Reader) (ds.Map[types.IdentityKey, *lindell22.Shard], error) {
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not validate protocol config")
	}
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	if secret == nil || secret.ScalarField().Curve().Name() != protocol.Curve().Name() {
		return nil, errs.NewValidation("invalid secret")
	}

	schnorrPrivateKey := secret.Clone()
	signingKeyShares, partialPublicKeys, err := trusted_dealer.Deal(protocol, schnorrPrivateKey, prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not deal shares")
	}

	shards := hashmap.NewHashableHashMap[types.IdentityKey, *lindell22.Shard]()
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

		shards.Put(identityKey, &lindell22.Shard{
			SigningKeyShare: sks,
			PublicKeyShares: ppk,
		})
	}

	return shards, nil
}
