package trusted_dealer

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/base/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/threshold/sharing/feldman"
	"github.com/copperexchange/knox-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/knox-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"

	"github.com/copperexchange/knox-primitives/pkg/base/curves"

	"github.com/copperexchange/knox-primitives/pkg/base/errs"
	"github.com/copperexchange/knox-primitives/pkg/base/integration"
	"github.com/copperexchange/knox-primitives/pkg/base/protocols"
)

func Keygen(cohortConfig *integration.CohortConfig, prng io.Reader) (map[helper_types.IdentityHash]*lindell22.Shard, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "could not validate cohort config")
	}

	if cohortConfig.Protocol.Name != protocols.LINDELL22 {
		return nil, errs.NewInvalidArgument("protocol %s not supported", cohortConfig.Protocol.Name)
	}

	curve := cohortConfig.CipherSuite.Curve
	schnorrPrivateKey := curve.Scalar().Random(prng)
	schnorrPublicKey := curve.ScalarBaseMult(schnorrPrivateKey)

	dealer, err := feldman.NewDealer(cohortConfig.Protocol.Threshold, cohortConfig.Protocol.TotalParties, curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct feldman dealer")
	}

	_, shamirShares, err := dealer.Split(schnorrPrivateKey, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to deal the secret")
	}

	sharingIdsToIdentityKeys, _, _ := integration.DeriveSharingIds(nil, cohortConfig.Participants)

	publicKeySharesMap := make(map[helper_types.IdentityHash]curves.Point)
	for sharingId, identityKey := range sharingIdsToIdentityKeys {
		publicKeySharesMap[identityKey.Hash()] = curve.ScalarBaseMult(shamirShares[sharingId-1].Value)
	}

	shards := make(map[helper_types.IdentityHash]*lindell22.Shard)
	for sharingId, identityKey := range sharingIdsToIdentityKeys {
		share := shamirShares[sharingId-1].Value
		shards[identityKey.Hash()] = &lindell22.Shard{
			SigningKeyShare: &tsignatures.SigningKeyShare{
				Share:     share,
				PublicKey: schnorrPublicKey,
			},
			PublicKeyShares: &tsignatures.PublicKeyShares{
				Curve:     curve,
				PublicKey: schnorrPublicKey,
				SharesMap: publicKeySharesMap,
			},
		}
	}

	return shards, nil
}
