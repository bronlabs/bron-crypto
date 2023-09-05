package trusted_dealer

import (
	"crypto/ecdsa"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/curveutils"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/encryptions/paillier"
	"github.com/cronokirby/saferith"
	"io"

	"github.com/copperexchange/knox-primitives/pkg/datastructures/types"

	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/p256"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/copperexchange/knox-primitives/pkg/sharing/feldman"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17"
)

const (
	// This is the `p` and `q` prime bit length which makes Paillier modulus to be 2048 bits long.
	// It allows us to make either two homomorphic multiplications (being repetitive homomorphic additions)
	// or one homomorphic multiplication with a bunch of homomorphic additions
	// for curves that have up to 512 bits long subgroup order.
	paillierPrimeBitLength = 1024
)

func verifyShards(cohortConfig *integration.CohortConfig, shards map[helper_types.IdentityHash]*lindell17.Shard, ecdsaPrivateKey *ecdsa.PrivateKey) error {
	sharingIdToIdentity, _, _ := integration.DeriveSharingIds(nil, cohortConfig.Participants)

	// verify private key
	feldmanShares := make([]*feldman.Share, len(shards))
	for i := range feldmanShares {
		sharingId := i + 1
		feldmanShares[i] = &feldman.Share{
			Id:    sharingId,
			Value: shards[sharingIdToIdentity[sharingId].Hash()].SigningKeyShare.Share,
		}
	}
	dealer, err := feldman.NewDealer(cohortConfig.Protocol.Threshold, cohortConfig.Protocol.TotalParties, cohortConfig.CipherSuite.Curve)
	if err != nil {
		return errs.WrapVerificationFailed(err, "cannot create Feldman dealer")
	}
	recoveredPrivateKey, err := dealer.Combine(feldmanShares...)
	if err != nil {
		return errs.WrapVerificationFailed(err, "cannot combine Feldman shares")
	}
	if recoveredPrivateKey.Nat().Big().Cmp(ecdsaPrivateKey.D) != 0 {
		return errs.NewVerificationFailed("recovered ECDSA private key is invalid")
	}

	// verify public key
	fieldOrder := cohortConfig.CipherSuite.Curve.Profile().Field().Order()
	recoveredPublicKey := cohortConfig.CipherSuite.Curve.ScalarBaseMult(recoveredPrivateKey)
	publicKey, err := cohortConfig.CipherSuite.Curve.Point().Set(
		new(saferith.Nat).SetBig(ecdsaPrivateKey.X, fieldOrder.BitLen()),
		new(saferith.Nat).SetBig(ecdsaPrivateKey.Y, fieldOrder.BitLen()),
	)
	if err != nil {
		return errs.WrapVerificationFailed(err, "invalid ECDSA public key")
	}
	if !publicKey.Equal(recoveredPublicKey) {
		return errs.NewVerificationFailed("recovered ECDSA public key is invalid")
	}
	for _, shard := range shards {
		if !shard.SigningKeyShare.PublicKey.Equal(publicKey) {
			return errs.NewVerificationFailed("shard has invalid public key")
		}
	}

	// verify Paillier encryption of shards
	for myIdentityKey, myShard := range shards {
		myShare := myShard.SigningKeyShare.Share.Nat()
		myPaillierPrivateKey := myShard.PaillierSecretKey
		for _, theirShard := range shards {
			if myShard.PaillierSecretKey.N.Nat().Eq(theirShard.PaillierSecretKey.N.Nat()) == 0 && myShard.PaillierSecretKey.N2.Nat().Eq(theirShard.PaillierSecretKey.N2.Nat()) == 0 {
				theirEncryptedShare := theirShard.PaillierEncryptedShares[myIdentityKey]
				decryptor, err := paillier.NewDecryptor(myPaillierPrivateKey)
				if err != nil {
					return errs.WrapVerificationFailed(err, "cannot create paillier decryptor")
				}
				theirDecryptedShare, err := decryptor.Decrypt(theirEncryptedShare)
				if err != nil {
					return errs.WrapVerificationFailed(err, "cannot verify encrypted share")
				}
				if theirDecryptedShare.Eq(myShare) == 0 {
					return errs.NewVerificationFailed("cannot decrypt encrypted share")
				}
			}
		}
	}

	return nil
}

func Keygen(cohortConfig *integration.CohortConfig, prng io.Reader) (map[helper_types.IdentityHash]*lindell17.Shard, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "could not validate cohort config")
	}

	if cohortConfig.Protocol.Name != protocols.LINDELL17 {
		return nil, errs.NewInvalidArgument("protocol %s not supported", cohortConfig.Protocol.Name)
	}

	curve := cohortConfig.CipherSuite.Curve
	if curve.Name() != k256.Name && curve.Name() != p256.Name {
		return nil, errs.NewInvalidArgument("curve should be K256 or P256 where as it is %s", cohortConfig.CipherSuite.Curve.Name())
	}

	eCurve, err := curveutils.ToEllipticCurve(curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert knox curve to go curve")
	}

	ecdsaPrivateKey, err := ecdsa.GenerateKey(eCurve, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate ECDSA private key")
	}

	privateKey, err := curve.Scalar().SetNat(new(saferith.Nat).SetBig(ecdsaPrivateKey.D, curve.Profile().SubGroupOrder().BitLen()))
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not convert go private key bytes to a knox scalar")
	}

	publicKey, err := cohortConfig.CipherSuite.Curve.Point().Set(
		new(saferith.Nat).SetBig(ecdsaPrivateKey.X, curve.Profile().Field().Order().BitLen()),
		new(saferith.Nat).SetBig(ecdsaPrivateKey.Y, curve.Profile().Field().Order().BitLen()),
	)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not convert go public key bytes to a knox point")
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
	shards := make(map[helper_types.IdentityHash]*lindell17.Shard)
	for sharingId, identityKey := range sharingIdsToIdentityKeys {
		share := shamirShares[sharingId-1].Value
		shards[identityKey.Hash()] = &lindell17.Shard{
			SigningKeyShare: &threshold.SigningKeyShare{
				Share:     share,
				PublicKey: publicKey,
			},
			PaillierPublicKeys:      make(map[helper_types.IdentityHash]*paillier.PublicKey),
			PaillierEncryptedShares: make(map[helper_types.IdentityHash]*paillier.CipherText),
		}
	}

	// generate Paillier key pairs and encrypt share
	for _, identityKey := range sharingIdsToIdentityKeys {
		paillierPublicKey, paillierSecretKey, err := paillier.NewKeys(paillierPrimeBitLength)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot generate paillier keys")
		}
		shards[identityKey.Hash()].PaillierSecretKey = paillierSecretKey
		for _, otherIdentityKey := range sharingIdsToIdentityKeys {
			if !types.Equals(identityKey, otherIdentityKey) {
				shards[otherIdentityKey.Hash()].PaillierPublicKeys[identityKey.Hash()] = paillierPublicKey
				shards[otherIdentityKey.Hash()].PaillierEncryptedShares[identityKey.Hash()], _, err = paillierPublicKey.Encrypt(shards[identityKey.Hash()].SigningKeyShare.Share.Nat())
				if err != nil {
					return nil, errs.WrapFailed(err, "cannot encrypt share with paillier")
				}
			}
		}
	}

	err = verifyShards(cohortConfig, shards, ecdsaPrivateKey)
	if err != nil {
		return nil, errs.NewVerificationFailed("failed to verify shards")
	}

	return shards, nil
}
