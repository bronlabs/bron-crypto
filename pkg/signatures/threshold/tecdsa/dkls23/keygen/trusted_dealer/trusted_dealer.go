package trusted_dealer

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves/native"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/feldman"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/dkls23"
)

// TODO: trusted dealer does not currently support identifiable abort
func Keygen(cohortConfig *integration.CohortConfig, prng io.Reader) (map[integration.IdentityKey]*dkls23.Shard, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "could not validate cohort config")
	}

	if cohortConfig.CipherSuite.Curve.Name != curves.K256Name {
		return nil, errs.NewInvalidArgument("curve should be K256 where as it is %s", cohortConfig.CipherSuite.Curve.Name)
	}
	if cohortConfig.Protocol != protocol.DKLS23 {
		return nil, errs.NewInvalidArgument("protocol not supported")
	}

	curve := curves.K256()
	eCurve, err := curve.ToEllipticCurve()
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert knox curve to go curve")
	}
	privateKeyBigInt, err := ecdsa.GenerateKey(eCurve, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate ecdsa private key")
	}
	privateKey, err := curve.Scalar.SetBigInt(privateKeyBigInt.X)
	if err != nil {
		return nil, errs.WrapDeserializationFailed(err, "could not convert ed25519 private key bytes to an ed25519 scalar")
	}
	publicKey := curve.ScalarBaseMult(privateKey)

	dealer, err := feldman.NewDealer(cohortConfig.Threshold, cohortConfig.TotalParties, curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct feldman dealer")
	}
	_, shamirShares, err := dealer.Split(privateKey, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to deal the secret")
	}

	shamirIdsToIdentityKeys, _, _ := integration.DeriveSharingIds(cohortConfig.Participants[0], cohortConfig.Participants)

	results := map[integration.IdentityKey]*dkls23.Shard{}

	for shamirId, identityKey := range shamirIdsToIdentityKeys {
		share := shamirShares[shamirId-1].Value
		results[identityKey] = &dkls23.Shard{
			SigningKeyShare: &dkls23.SigningKeyShare{
				Share:     share,
				PublicKey: publicKey,
			},
			// Not currently supported
			PublicKeyShares: nil,
			PairwiseSeeds:   dkls23.PairwiseSeeds{},
		}
	}

	for identityKey := range results {
		for otherIdentityKey := range results {
			if identityKey.PublicKey().Equal(otherIdentityKey.PublicKey()) {
				continue
			}
			randomSeed := [native.FieldBytes]byte{}
			if _, err := crand.Read(randomSeed[:]); err != nil {
				return nil, errs.WrapFailed(err, "could not produce random seed")
			}
			results[identityKey].PairwiseSeeds[otherIdentityKey] = randomSeed
		}
	}
	return results, nil

}
