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
	if publicKey.CurveName() == curves.ED25519Name {
		edwardsPoint, ok := publicKey.(*curves.PointEd25519)
		if !ok {
			return nil, errors.New("curve is ed25519 but the public key could not be type casted to the correct point struct")
		}
		// this check is not part of the ed25519 standard yet if the public key is of small order then the signature will be susceptibe
		// to a key substitution attack (specifically, it won't have message bound security). Refer to section 5.4 of https://eprint.iacr.org/2020/823.pdf and https://eprint.iacr.org/2020/1244.pdf
		if edwardsPoint.IsSmallOrder() {
			return nil, errors.New("public key is small order")
		}
	}

	feldmanDealer, err := sharing.NewFeldman(cohortConfig.Threshold, cohortConfig.TotalParties, curve)
	if err != nil {
		return nil, errors.Wrap(err, "could not construct feldman dealer")
	}
	_, shamirShares, err := feldmanDealer.Split(privateKey, reader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to deal the secret")
	}

	shamirIdsToIdentityKeys, _, _, err := frost.DeriveShamirIds(cohortConfig.Participants[0], cohortConfig.Participants)
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
