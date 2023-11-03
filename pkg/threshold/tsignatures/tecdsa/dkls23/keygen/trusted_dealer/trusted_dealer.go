package trusted_dealer

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/constants"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"

	core "github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/feldman"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23"
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
)

// TODO: trusted dealer does not currently support identifiable abort
func Keygen(cohortConfig *integration.CohortConfig, prng io.Reader) (map[types.IdentityHash]*dkls23.Shard, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "could not validate cohort config")
	}

	if cohortConfig.CipherSuite.Curve.Name() != k256.Name && cohortConfig.CipherSuite.Curve.Name() != p256.Name {
		return nil, errs.NewInvalidArgument("curve should be K256 or P256 where as it is %s", cohortConfig.CipherSuite.Curve.Name())
	}
	if cohortConfig.Protocol.Name != protocols.DKLS23 {
		return nil, errs.NewInvalidArgument("protocol not supported")
	}

	curve := k256.New()
	eCurve, err := curveutils.ToEllipticCurve(curve)
	ecdsaPrivateKey, err := ecdsa.GenerateKey(eCurve, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate ECDSA private key")
	}
	privateKey, err := curve.Scalar().SetNat(new(saferith.Nat).SetBig(ecdsaPrivateKey.D, curve.Profile().SubGroupOrder().BitLen()))
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not convert go private key bytes to a krypton scalar")
	}
	publicKey, err := cohortConfig.CipherSuite.Curve.Point().Set(
		core.NatFromBig(ecdsaPrivateKey.X, cohortConfig.CipherSuite.Curve.Profile().SubGroupOrder()),
		core.NatFromBig(ecdsaPrivateKey.Y, cohortConfig.CipherSuite.Curve.Profile().SubGroupOrder()),
	)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not convert go public key bytes to a krypton point")
	}
	calculatedPublicKey := curve.ScalarBaseMult(privateKey)
	if !calculatedPublicKey.Equal(publicKey) {
		return nil, errs.NewVerificationFailed("calculated public key is incorrect")
	}

	dealer, err := feldman.NewDealer(cohortConfig.Protocol.Threshold, cohortConfig.Protocol.TotalParties, curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct feldman dealer")
	}
	_, shamirShares, err := dealer.Split(privateKey, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to deal the secret")
	}

	sharingIdsToIdentityKeys, _, _ := integration.DeriveSharingIds(nil, cohortConfig.Participants)

	results := map[types.IdentityHash]*dkls23.Shard{}

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
			randomSeed := [constants.FieldBytes]byte{}
			if _, err := crand.Read(randomSeed[:]); err != nil {
				return nil, errs.WrapRandomSampleFailed(err, "could not produce random seed")
			}
			results[identityKey].PairwiseSeeds[otherIdentityKey] = randomSeed
		}
	}
	return results, nil

}
