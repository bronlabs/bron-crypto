package trusted_dealer

import (
	"crypto/ed25519"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/error_types"
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	"github.com/pkg/errors"
)

// TODO: trusted dealer does not currently support identifiable abort
func Keygen(cohortConfig *integration.CohortConfig, prng io.Reader) (map[integration.IdentityKey]*frost.SigningKeyShare, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errors.Wrapf(err, "%s could not validate cohort config", error_types.EVerificationFailed)
	}

	curve := curves.ED25519()
	publicKeyBytes, privateKeyBytes, err := ed25519.GenerateKey(prng)
	if err != nil {
		return nil, errors.Wrapf(err, "%s could not generate ed25519 compliant private key", error_types.EAbort)
	}
	privateKey, err := curve.Scalar.SetBytesWide(privateKeyBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "%s could not convert ed25519 private key bytes to an ed25519 scalar", error_types.EDeserializationFailed)
	}
	publicKey, err := curve.Point.FromAffineCompressed(publicKeyBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "%s could not convert ed25519 public key bytes to an ed25519 point", error_types.EDeserializationFailed)
	}

	feldmanDealer, err := sharing.NewFeldman(cohortConfig.Threshold, cohortConfig.TotalParties, curve)
	if err != nil {
		return nil, errors.Wrapf(err, "%s could not construct feldman dealer", error_types.EAbort)
	}
	_, shamirShares, err := feldmanDealer.Split(privateKey, prng)
	if err != nil {
		return nil, errors.Wrapf(err, "%s failed to deal the secret", error_types.EAbort)
	}

	shamirIdsToIdentityKeys, _, _ := frost.DeriveShamirIds(cohortConfig.Participants[0], cohortConfig.Participants)

	results := map[integration.IdentityKey]*frost.SigningKeyShare{}

	for shamirId, identityKey := range shamirIdsToIdentityKeys {
		share := shamirShares[shamirId-1].Value
		results[identityKey] = &frost.SigningKeyShare{
			Share:     share,
			PublicKey: publicKey,
		}
	}
	return results, nil

}
