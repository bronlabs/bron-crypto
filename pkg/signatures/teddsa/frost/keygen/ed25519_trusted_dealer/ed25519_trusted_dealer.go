package trusted_dealer

import (
	"crypto/ed25519"
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	"github.com/pkg/errors"
)

// TODO: trusted dealer does not currently support identifiable abort
func Keygen(cohortConfig *integration.CohortConfig, reader io.Reader) (map[integration.IdentityKey]*frost.SigningKeyShare, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errors.Wrap(err, "could not validate cohort config")
	}

	curve := curves.ED25519()
	publicKeyBytes, privateKeyBytes, err := ed25519.GenerateKey(reader)
	if err != nil {
		return nil, errors.Wrap(err, "could not generate ed25519 compliant private key")
	}
	privateKey, err := curve.Scalar.SetBytesWide(privateKeyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "could not convert ed25519 private key bytes to an ed25519 scalar")
	}
	publicKey, err := curve.Point.FromAffineCompressed(publicKeyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "could not convert ed25519 public key bytes to an ed25519 point")
	}

	feldmanDealer, err := sharing.NewFeldman(uint32(cohortConfig.Threshold), uint32(cohortConfig.TotalParties), curve)
	if err != nil {
		return nil, errors.Wrap(err, "could not construct feldman dealer")
	}
	_, shamirShares, err := feldmanDealer.Split(privateKey, reader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to deal the secret")
	}

	shamirIdsToIdentityKeys, _, err := frost.DeriveShamirIds(cohortConfig.Participants[0], cohortConfig.Participants)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't derive shamir ids")
	}

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
