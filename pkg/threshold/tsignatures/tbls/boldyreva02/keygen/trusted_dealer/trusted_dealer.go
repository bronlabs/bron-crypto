package trusted_dealer

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/feldman"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02"
)

func Keygen[K bls.KeySubGroup](cohortConfig *integration.CohortConfig, prng io.Reader) (map[types.IdentityHash]*boldyreva02.Shard[K], error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "could not validate cohort config")
	}

	if cohortConfig.Protocol == nil {
		return nil, errs.NewInvalidArgument("protocol information is nil")
	}

	if cohortConfig.Protocol.Name != protocols.BLS {
		return nil, errs.NewInvalidArgument("protocol %s not supported", cohortConfig.Protocol.Name)
	}

	pointInK := new(K)
	subGroup := (*pointInK).Curve()

	if cohortConfig.CipherSuite.Curve.Name() != subGroup.Name() {
		return nil, errs.NewInvalidCurve("cohort's subgroup is not the same the generic type")
	}

	if prng == nil {
		return nil, errs.NewInvalidArgument("prng is nil")
	}

	privateKey, err := bls.KeyGen[K](prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to do keygen")
	}

	dealer, err := feldman.NewDealer(cohortConfig.Protocol.Threshold, cohortConfig.Participants.Len(), subGroup)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct feldman dealer")
	}

	_, shamirShares, err := dealer.Split(privateKey.D(), prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to deal the secret")
	}

	sharingIdsToIdentityKeys, _, _ := integration.DeriveSharingIds(nil, cohortConfig.Participants)

	publicKeySharesMap := make(map[types.IdentityHash]curves.PairingPoint)
	for sharingId, identityKey := range sharingIdsToIdentityKeys {
		share, ok := subGroup.ScalarBaseMult(shamirShares[sharingId-1].Value).(curves.PairingPoint)
		if !ok {
			return nil, errs.NewInvalidType("public key share is not a pairing point")
		}
		publicKeySharesMap[identityKey.Hash()] = share
	}

	shards := make(map[types.IdentityHash]*boldyreva02.Shard[K])
	for sharingId, identityKey := range sharingIdsToIdentityKeys {
		share, ok := shamirShares[sharingId-1].Value.(curves.PairingScalar)
		if !ok {
			return nil, errs.NewInvalidType("share is not a pairing scalar")
		}
		shards[identityKey.Hash()] = &boldyreva02.Shard[K]{
			SigningKeyShare: &boldyreva02.SigningKeyShare[K]{
				Share:     share,
				PublicKey: privateKey.PublicKey,
			},
			PublicKeyShares: &boldyreva02.PublicKeyShares[K]{
				PublicKey: privateKey.PublicKey,
				SharesMap: publicKeySharesMap,
			},
		}
	}

	return shards, nil
}
