package trusted_dealer

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"

	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
)

// TODO: trusted dealer does not currently support identifiable abort
func Keygen(cohortConfig *integration.CohortConfig, prng io.Reader) (map[types.IdentityHash]*dkls24.Shard, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "could not validate cohort config")
	}

	if cohortConfig.CipherSuite.Curve.Name() != k256.Name && cohortConfig.CipherSuite.Curve.Name() != p256.Name {
		return nil, errs.NewInvalidArgument("curve should be K256 or P256 where as it is %s", cohortConfig.CipherSuite.Curve.Name())
	}
	if cohortConfig.Protocol.Name != protocols.DKLS24 {
		return nil, errs.NewInvalidArgument("protocol not supported")
	}

	curve := k256.NewCurve()
	eCurve, err := curveutils.ToGoEllipticCurve(curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert krypton curve to elliptic curve")
	}
	ecdsaPrivateKey, err := ecdsa.GenerateKey(eCurve, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate ECDSA private key")
	}
	privateKey := curve.Scalar().SetNat(new(saferith.Nat).SetBig(ecdsaPrivateKey.D, curve.SubGroupOrder().BitLen()))
	px := cohortConfig.CipherSuite.Curve.BaseField().Element().SetNat(
		utils.Saferith.NatFromBig(ecdsaPrivateKey.X, cohortConfig.CipherSuite.Curve.SubGroupOrder()),
	)
	py := cohortConfig.CipherSuite.Curve.BaseField().Element().SetNat(
		utils.Saferith.NatFromBig(ecdsaPrivateKey.Y, cohortConfig.CipherSuite.Curve.SubGroupOrder()),
	)
	publicKey, err := cohortConfig.CipherSuite.Curve.NewPoint(px, py)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not convert go public key bytes to a krypton point")
	}
	calculatedPublicKey := curve.ScalarBaseMult(privateKey)
	if !calculatedPublicKey.Equal(publicKey) {
		return nil, errs.NewVerificationFailed("calculated public key is incorrect")
	}

	dealer, err := shamir.NewDealer(cohortConfig.Protocol.Threshold, cohortConfig.Protocol.TotalParties, curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct feldman dealer")
	}
	shamirShares, err := dealer.Split(privateKey, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to deal the secret")
	}

	sharingIdsToIdentityKeys, _, _ := integration.DeriveSharingIds(nil, cohortConfig.Participants)

	results := map[types.IdentityHash]*dkls24.Shard{}

	for sharingId, identityKey := range sharingIdsToIdentityKeys {
		share := shamirShares[sharingId-1].Value
		results[identityKey.Hash()] = &dkls24.Shard{
			SigningKeyShare: &dkls24.SigningKeyShare{
				Share:     share,
				PublicKey: publicKey,
			},
			// Not currently supported
			PublicKeyShares: nil,
		}
	}

	for identityKey := range results {
		for otherIdentityKey := range results {
			if identityKey == otherIdentityKey {
				continue
			}
			randomSeed := [base.FieldBytes]byte{}
			if _, err := crand.Read(randomSeed[:]); err != nil {
				return nil, errs.WrapRandomSampleFailed(err, "could not produce random seed")
			}
		}
	}
	return results, nil

}
