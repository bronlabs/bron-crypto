package trusted_dealer

import (
	"crypto/ecdsa"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/curveutils"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	saferithUtils "github.com/bronlabs/bron-crypto/pkg/base/utils/saferith"
	"github.com/bronlabs/bron-crypto/pkg/threshold/trusted_dealer"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/dkls23"
)

func Keygen(protocol types.ThresholdProtocol, prng io.Reader) (ds.Map[types.IdentityKey, *dkls23.Shard], error) {
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return nil, errs.WrapVerification(err, "could not validate protocol config")
	}
	if protocol.Curve().Name() != k256.Name && protocol.Curve().Name() != p256.Name {
		return nil, errs.NewArgument("curve should be K256 or P256 where as it is %s", protocol.Curve().Name())
	}

	eCurve, err := curveutils.ToGoEllipticCurve(protocol.Curve())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert bron curve to elliptic curve")
	}
	ecdsaPrivateKey, err := ecdsa.GenerateKey(eCurve, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate ECDSA private key")
	}
	privateKey := protocol.Curve().ScalarField().Element().SetNat(new(saferith.Nat).SetBig(ecdsaPrivateKey.D, protocol.Curve().Order().BitLen()))
	px := protocol.Curve().BaseField().Element().SetNat(
		saferithUtils.NatFromBigMod(ecdsaPrivateKey.X, protocol.Curve().Order()),
	)
	py := protocol.Curve().BaseField().Element().SetNat(
		saferithUtils.NatFromBigMod(ecdsaPrivateKey.Y, protocol.Curve().Order()),
	)
	publicKey, err := protocol.Curve().NewPoint(px, py)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not convert go public key bytes to a bron point")
	}
	calculatedPublicKey := protocol.Curve().ScalarBaseMult(privateKey)
	if !calculatedPublicKey.Equal(publicKey) {
		return nil, errs.NewVerification("calculated public key is incorrect")
	}

	signingKeyShares, publicKeyShares, err := trusted_dealer.Deal(protocol, privateKey, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not deal shares")
	}

	results := hashmap.NewHashableHashMap[types.IdentityKey, *dkls23.Shard]()
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	for _, identityKey := range sharingConfig.Iter() {
		share, exists := signingKeyShares.Get(identityKey)
		if !exists {
			return nil, errs.NewFailed("signing key share is missing")
		}
		partialPublic, exists := publicKeyShares.Get(identityKey)
		if !exists {
			return nil, errs.NewFailed("partial public key is missing")
		}

		results.Put(identityKey, &dkls23.Shard{
			SigningKeyShare: share,
			PublicKeyShares: partialPublic,
		})
	}

	return results, nil
}
