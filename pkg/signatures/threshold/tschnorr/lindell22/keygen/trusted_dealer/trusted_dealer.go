package trusted_dealer

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/feldman"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold"
	"io"
)

func Keygen(cohortConfig *integration.CohortConfig, prng io.Reader) (map[integration.IdentityKey]*threshold.SigningKeyShare, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "could not validate cohort config")
	}

	if cohortConfig.Protocol != protocol.LINDELL22 {
		return nil, errs.NewInvalidArgument("protocol %s not supported", cohortConfig.Protocol)
	}

	curve := cohortConfig.CipherSuite.Curve
	schnorrPrivateKey := curve.NewScalar().Random(prng)
	schnorrPublicKey := curve.ScalarBaseMult(schnorrPrivateKey)

	dealer, err := feldman.NewDealer(cohortConfig.Threshold, cohortConfig.TotalParties, curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct feldman dealer")
	}

	_, shamirShares, err := dealer.Split(schnorrPrivateKey, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to deal the secret")
	}

	shamirIdsToIdentityKeys, _, _ := integration.DeriveSharingIds(cohortConfig.Participants[0], cohortConfig.Participants)
	shards := make(map[integration.IdentityKey]*threshold.SigningKeyShare)
	for shamirId, identityKey := range shamirIdsToIdentityKeys {
		share := shamirShares[shamirId-1].Value
		shards[identityKey] = &threshold.SigningKeyShare{
			Share:     share,
			PublicKey: schnorrPublicKey,
		}
	}

	return shards, nil
}
