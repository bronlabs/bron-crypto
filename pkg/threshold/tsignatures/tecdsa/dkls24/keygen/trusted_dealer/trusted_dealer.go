package trusted_dealer

import (
	"crypto/ecdsa"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/threshold/trusted_dealer"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

func Keygen(protocol types.ThresholdProtocol, prng io.Reader) (ds.Map[types.IdentityKey, *dkls24.Shard], error) {
	if err := types.ValidateThresholdProtocol(protocol); err != nil {
		return nil, errs.WrapVerification(err, "could not validate protocol config")
	}
	if protocol.Curve().Name() != k256.Name && protocol.Curve().Name() != p256.Name {
		return nil, errs.NewArgument("curve should be K256 or P256 where as it is %s", protocol.Curve().Name())
	}

	eCurve, err := curveutils.ToGoEllipticCurve(protocol.Curve())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert krypton curve to elliptic curve")
	}
	ecdsaPrivateKey, err := ecdsa.GenerateKey(eCurve, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate ECDSA private key")
	}
	privateKey := protocol.Curve().Scalar().SetNat(new(saferith.Nat).SetBig(ecdsaPrivateKey.D, protocol.Curve().SubGroupOrder().BitLen()))
	px := protocol.Curve().BaseField().Element().SetNat(
		utils.NatFromBig(ecdsaPrivateKey.X, protocol.Curve().SubGroupOrder()),
	)
	py := protocol.Curve().BaseField().Element().SetNat(
		utils.NatFromBig(ecdsaPrivateKey.Y, protocol.Curve().SubGroupOrder()),
	)
	publicKey, err := protocol.Curve().NewPoint(px, py)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not convert go public key bytes to a krypton point")
	}
	calculatedPublicKey := protocol.Curve().ScalarBaseMult(privateKey)
	if !calculatedPublicKey.Equal(publicKey) {
		return nil, errs.NewVerification("calculated public key is incorrect")
	}

	signingKeyShares, publicKeyShares, err := trusted_dealer.Deal(protocol, privateKey, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not deal shares")
	}

	results := hashmap.NewHashableHashMap[types.IdentityKey, *dkls24.Shard]()
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	for pair := range sharingConfig.Iter() {
		identityKey := pair.Value
		share, exists := signingKeyShares.Get(identityKey)
		if !exists {
			return nil, errs.NewFailed("signing key share is missing")
		}
		partialPublic, exists := publicKeyShares.Get(identityKey)
		if !exists {
			return nil, errs.NewFailed("partial public key is missing")
		}

		results.Put(identityKey, &dkls24.Shard{
			SigningKeyShare: share,
			PublicKeyShares: partialPublic,
			PairwiseBaseOTs: nil,
		})
	}

	for _, identityKey := range results.Keys() {
		for _, otherIdentityKey := range results.Keys() {
			if identityKey.Equal(otherIdentityKey) {
				continue
			}
			randomSeed := [base.FieldBytes]byte{}
			if _, err := io.ReadFull(prng, randomSeed[:]); err != nil {
				return nil, errs.WrapRandomSample(err, "could not produce random seed")
			}
		}
	}
	return results, nil

}
