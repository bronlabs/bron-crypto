package trusted_dealer

import (
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22"

	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/copperexchange/knox-primitives/pkg/sharing/feldman"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold"
)

func Keygen(cohortConfig *integration.CohortConfig, prng io.Reader) (map[helper_types.IdentityHash]*lindell22.Shard, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "could not validate cohort config")
	}

	if cohortConfig.Protocol != protocols.LINDELL22 {
		return nil, errs.NewInvalidArgument("protocol %s not supported", cohortConfig.Protocol)
	}

	curve := cohortConfig.CipherSuite.Curve
	schnorrPrivateKey := curve.Scalar().Random(prng)
	schnorrPublicKey := curve.ScalarBaseMult(schnorrPrivateKey)

	dealer, err := feldman.NewDealer(cohortConfig.Threshold, cohortConfig.TotalParties, curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct feldman dealer")
	}

	_, shamirShares, err := dealer.Split(schnorrPrivateKey, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to deal the secret")
	}

	sharingIdsToIdentityKeys, _, _ := integration.DeriveSharingIds(cohortConfig.Participants[0], cohortConfig.Participants)

	publicKeySharesMap := make(map[helper_types.IdentityHash]curves.Point)
	for sharingId, identityKey := range sharingIdsToIdentityKeys {
		publicKeySharesMap[identityKey.Hash()] = curve.ScalarBaseMult(shamirShares[sharingId-1].Value)
	}

	shards := make(map[helper_types.IdentityHash]*lindell22.Shard)
	for sharingId, identityKey := range sharingIdsToIdentityKeys {
		share := shamirShares[sharingId-1].Value
		shards[identityKey.Hash()] = &lindell22.Shard{
			SigningKeyShare: &threshold.SigningKeyShare{
				Share:     share,
				PublicKey: schnorrPublicKey,
			},
			PublicKeyShares: &threshold.PublicKeyShares{
				Curve:     curve,
				PublicKey: schnorrPublicKey,
				SharesMap: publicKeySharesMap,
			},
		}
	}

	return shards, nil
}
