package trusted_dealer

import (
	"crypto/ed25519"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
)

// TODO: trusted dealer does not currently support identifiable abort
func Keygen(cohortConfig *integration.CohortConfig, prng io.Reader) (map[integration.IdentityKey]*frost.SigningKeyShare, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "could not validate cohort config")
	}

	curve := curves.ED25519()
	publicKeyBytes, privateKeyBytes, err := ed25519.GenerateKey(prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate ed25519 compliant private key")
	}
	privateKey, err := curve.Scalar.SetBytesWide(privateKeyBytes)
	if err != nil {
		return nil, errs.WrapDeserializationFailed(err, "could not convert ed25519 private key bytes to an ed25519 scalar")
	}
	publicKey, err := curve.Point.FromAffineCompressed(publicKeyBytes)
	if err != nil {
		return nil, errs.WrapDeserializationFailed(err, "could not convert ed25519 public key bytes to an ed25519 point")
	}

	feldmanDealer, err := sharing.NewFeldman(cohortConfig.Threshold, cohortConfig.TotalParties, curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct feldman dealer")
	}
	_, shamirShares, err := feldmanDealer.Split(privateKey, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to deal the secret")
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
