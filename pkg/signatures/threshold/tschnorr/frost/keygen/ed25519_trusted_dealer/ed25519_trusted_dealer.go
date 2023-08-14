package trusted_dealer

import (
	"crypto/ed25519"
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/copperexchange/knox-primitives/pkg/sharing/feldman"

	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/frost"
)

// TODO: trusted dealer does not currently support identifiable abort
func Keygen(cohortConfig *integration.CohortConfig, prng io.Reader) (map[integration.IdentityHash]*frost.SigningKeyShare, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "could not validate cohort config")
	}
	if cohortConfig.CipherSuite.Curve.Name() != edwards25519.Name {
		return nil, errs.NewInvalidArgument("curve not supported")
	}
	if cohortConfig.Protocol != protocols.FROST {
		return nil, errs.NewInvalidArgument("protocol not supported")
	}
	curve := edwards25519.New()
	publicKeyBytes, privateKeyBytes, err := ed25519.GenerateKey(prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate ed25519 compliant private key")
	}
	privateKey, err := curve.Scalar().SetBytesWide(privateKeyBytes)
	if err != nil {
		return nil, errs.WrapDeserializationFailed(err, "could not convert ed25519 private key bytes to an ed25519 scalar")
	}
	publicKey, err := curve.Point().FromAffineCompressed(publicKeyBytes)
	if err != nil {
		return nil, errs.WrapDeserializationFailed(err, "could not convert ed25519 public key bytes to an ed25519 point")
	}

	dealer, err := feldman.NewDealer(cohortConfig.Threshold, cohortConfig.TotalParties, curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct feldman dealer")
	}
	_, shamirShares, err := dealer.Split(privateKey, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to deal the secret")
	}

	sharingIdsToIdentityKeys, _, _ := integration.DeriveSharingIds(cohortConfig.Participants[0], cohortConfig.Participants)

	results := map[integration.IdentityHash]*frost.SigningKeyShare{}

	for sharingId, identityKey := range sharingIdsToIdentityKeys {
		share := shamirShares[sharingId-1].Value
		results[identityKey.Hash()] = &frost.SigningKeyShare{
			Share:     share,
			PublicKey: publicKey,
		}
	}
	return results, nil

}
