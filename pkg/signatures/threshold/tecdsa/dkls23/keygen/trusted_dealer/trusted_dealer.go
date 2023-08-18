package trusted_dealer

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/curves/curveutils"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/p256"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/copperexchange/knox-primitives/pkg/sharing/feldman"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23"
)

// TODO: trusted dealer does not currently support identifiable abort
func Keygen(cohortConfig *integration.CohortConfig, prng io.Reader) (map[helper_types.IdentityHash]*dkls23.Shard, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "could not validate cohort config")
	}

	if cohortConfig.CipherSuite.Curve.Name() != k256.Name && cohortConfig.CipherSuite.Curve.Name() != p256.Name {
		return nil, errs.NewInvalidArgument("curve should be K256 or P256 where as it is %s", cohortConfig.CipherSuite.Curve.Name())
	}
	if cohortConfig.Protocol != protocols.DKLS23 {
		return nil, errs.NewInvalidArgument("protocol not supported")
	}

	curve := k256.New()
	eCurve, err := curveutils.ToEllipticCurve(curve)
	ecdsaPrivateKey, err := ecdsa.GenerateKey(eCurve, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate ECDSA private key")
	}
	privateKey, err := curve.Scalar().SetBigInt(ecdsaPrivateKey.D)
	if err != nil {
		return nil, errs.WrapDeserializationFailed(err, "could not convert go private key bytes to a knox scalar")
	}
	publicKey, err := curve.Point().Set(ecdsaPrivateKey.X, ecdsaPrivateKey.Y)
	if err != nil {
		return nil, errs.WrapDeserializationFailed(err, "could not convert go public key bytes to a knox point")
	}
	calculatedPublicKey := curve.ScalarBaseMult(privateKey)
	if !calculatedPublicKey.Equal(publicKey) {
		return nil, errs.NewVerificationFailed("calculated public key is incorrect")
	}

	dealer, err := feldman.NewDealer(cohortConfig.Threshold, cohortConfig.TotalParties, curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct feldman dealer")
	}
	_, shamirShares, err := dealer.Split(privateKey, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to deal the secret")
	}

	sharingIdsToIdentityKeys, _, _ := integration.DeriveSharingIds(nil, cohortConfig.Participants)

	results := map[helper_types.IdentityHash]*dkls23.Shard{}

	for sharingId, identityKey := range sharingIdsToIdentityKeys {
		share := shamirShares[sharingId-1].Value
		results[identityKey.Hash()] = &dkls23.Shard{
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
			if identityKey == otherIdentityKey {
				continue
			}
			randomSeed := [impl.FieldBytes]byte{}
			if _, err := crand.Read(randomSeed[:]); err != nil {
				return nil, errs.WrapFailed(err, "could not produce random seed")
			}
			results[identityKey].PairwiseSeeds[otherIdentityKey] = randomSeed
		}
	}
	return results, nil

}
