package trusted_dealer

import (
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
)

func Keygen(cohortConfig *integration.CohortConfig, prng io.Reader) (map[types.IdentityHash]*lindell22.Shard, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "could not validate cohort config")
	}

	if cohortConfig.Protocol.Name != protocols.LINDELL22 {
		return nil, errs.NewInvalidArgument("protocol %s not supported", cohortConfig.Protocol.Name)
	}

	curve := cohortConfig.CipherSuite.Curve
	schnorrPrivateKey, err := curve.ScalarField().Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "could not generate random schnorr private key")
	}
	schnorrPublicKey := curve.ScalarBaseMult(schnorrPrivateKey)

	dealer, err := shamir.NewDealer(cohortConfig.Protocol.Threshold, cohortConfig.Protocol.TotalParties, curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct feldman dealer")
	}

	shamirShares, err := dealer.Split(schnorrPrivateKey, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to deal the secret")
	}

	sharingIdsToIdentityKeys, _, _ := integration.DeriveSharingIds(nil, cohortConfig.Participants)

	publicKeySharesMap := make(map[types.IdentityHash]curves.Point)
	for sharingId, identityKey := range sharingIdsToIdentityKeys {
		publicKeySharesMap[identityKey.Hash()] = curve.ScalarBaseMult(shamirShares[sharingId-1].Value)
	}

	shards := make(map[types.IdentityHash]*lindell22.Shard)
	for sharingId, identityKey := range sharingIdsToIdentityKeys {
		share := shamirShares[sharingId-1].Value
		shards[identityKey.Hash()] = &lindell22.Shard{
			SigningKeyShare: &tsignatures.SigningKeyShare{
				Share:     share,
				PublicKey: schnorrPublicKey,
			},
			PublicKeyShares: &tsignatures.PublicKeyShares{
				PublicKey: schnorrPublicKey,
				SharesMap: publicKeySharesMap,
			},
		}
	}

	return shards, nil
}
