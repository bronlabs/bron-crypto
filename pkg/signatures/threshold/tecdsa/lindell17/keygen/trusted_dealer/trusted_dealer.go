package trusted_dealer

import (
	"crypto/ecdsa"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashmap"
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/copperexchange/knox-primitives/pkg/paillier"
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

func verifyShards(cohortConfig *integration.CohortConfig, shards *hashmap.HashMap[integration.IdentityKey, *lindell17.Shard], ecdsaPrivateKey *ecdsa.PrivateKey) error {
	sharingIdToIdentity, _, _ := integration.DeriveSharingIds(nil, cohortConfig.Participants)

	// verify private key
	feldmanShares := make([]*feldman.Share, shards.Size())
	for i := range feldmanShares {
		sharingId := i + 1
		share, exists := shards.Get(sharingIdToIdentity[sharingId])
		if !exists {
			return errs.NewVerificationFailed("missing shard")
		}
		feldmanShares[i] = &feldman.Share{
			Id:    sharingId,
			Value: share.SigningKeyShare.Share,
		}
	}
	dealer, err := feldman.NewDealer(cohortConfig.Threshold, cohortConfig.TotalParties, cohortConfig.CipherSuite.Curve)
	if err != nil {
		return errs.WrapVerificationFailed(err, "cannot create Feldman dealer")
	}
	recoveredPrivateKey, err := dealer.Combine(feldmanShares...)
	if err != nil {
		return errs.WrapVerificationFailed(err, "cannot combine Feldman shares")
	}
	if recoveredPrivateKey.BigInt().Cmp(ecdsaPrivateKey.D) != 0 {
		return errs.NewVerificationFailed("recovered ECDSA private key is invalid")
	}

	// verify public key
	recoveredPublicKey := cohortConfig.CipherSuite.Curve.ScalarBaseMult(recoveredPrivateKey)
	publicKey, err := cohortConfig.CipherSuite.Curve.Point.Set(ecdsaPrivateKey.X, ecdsaPrivateKey.Y)
	if err != nil {
		return errs.WrapVerificationFailed(err, "invalid ECDSA public key")
	}
	if !publicKey.Equal(recoveredPublicKey) {
		return errs.NewVerificationFailed("recovered ECDSA public key is invalid")
	}
	for _, shard := range shards.GetMap() {
		if !shard.SigningKeyShare.PublicKey.Equal(publicKey) {
			return errs.NewVerificationFailed("shard has invalid public key")
		}
	}

	// verify Paillier encryption of shards
	for myIdentityKey, myShard := range shards.GetMap() {
		myShare := myShard.SigningKeyShare.Share.BigInt()
		myPaillierPrivateKey := myShard.PaillierSecretKey
		for _, theirShard := range shards.GetMap() {
			if myShard != theirShard {
				theirEncryptedShare, exists := theirShard.PaillierEncryptedShares.Get(myIdentityKey)
				if !exists {
					return errs.NewVerificationFailed("missing encrypted share")
				}
				theirDecryptedShare, err := myPaillierPrivateKey.Decrypt(theirEncryptedShare)
				if err != nil {
					return errs.WrapVerificationFailed(err, "cannot verify encrypted share")
				}
				if theirDecryptedShare.Cmp(myShare) != 0 {
					return errs.NewVerificationFailed("cannot decrypt encrypted share")
				}
			}
		}
	}

	return nil
}

func Keygen(cohortConfig *integration.CohortConfig, prng io.Reader) (*hashmap.HashMap[integration.IdentityKey, *lindell17.Shard], error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "could not validate cohort config")
	}

	if cohortConfig.Protocol != protocols.LINDELL17 {
		return nil, errs.NewInvalidArgument("protocol %s not supported", cohortConfig.Protocol)
	}

	curve := cohortConfig.CipherSuite.Curve
	if curve.Name != curves.K256Name && curve.Name != curves.P256Name {
		return nil, errs.NewInvalidArgument("curve should be K256 or P256 where as it is %s", cohortConfig.CipherSuite.Curve.Name)
	}

	eCurve, err := curve.ToEllipticCurve()
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert knox curve to go curve")
	}

	ecdsaPrivateKey, err := ecdsa.GenerateKey(eCurve, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate ECDSA private key")
	}

	privateKey, err := curve.Scalar.SetBigInt(ecdsaPrivateKey.D)
	if err != nil {
		return nil, errs.WrapDeserializationFailed(err, "could not convert go private key bytes to a knox scalar")
	}

	publicKey, err := curve.Point.Set(ecdsaPrivateKey.X, ecdsaPrivateKey.Y)
	if err != nil {
		return nil, errs.WrapDeserializationFailed(err, "could not convert go public key bytes to a knox point")
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
	shards := hashmap.NewHashMap[integration.IdentityKey, *lindell17.Shard]()
	for sharingId, identityKey := range sharingIdsToIdentityKeys {
		share := shamirShares[sharingId-1].Value
		shards.Put(identityKey, &lindell17.Shard{
			SigningKeyShare: &threshold.SigningKeyShare{
				Share:     share,
				PublicKey: publicKey,
			},
			PaillierPublicKeys:      hashmap.NewHashMap[integration.IdentityKey, *paillier.PublicKey](),
			PaillierEncryptedShares: hashmap.NewHashMap[integration.IdentityKey, paillier.CipherText](),
		})
	}

	// generate Paillier key pairs and encrypt share
	for _, identityKey := range sharingIdsToIdentityKeys {
		paillierPublicKey, paillierSecretKey, err := paillier.NewKeys(paillierPrimeBitLength)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot generate paillier keys")
		}
		shard, exists := shards.Get(identityKey)
		if !exists {
			return nil, errs.NewInvalidArgument("shard for identity key %s does not exist", identityKey)
		}
		shard.PaillierSecretKey = paillierSecretKey
		for _, otherIdentityKey := range sharingIdsToIdentityKeys {
			otherShard, exists := shards.Get(otherIdentityKey)
			if !exists {
				return nil, errs.NewInvalidArgument("shard for identity key %s does not exist", otherIdentityKey)
			}
			if identityKey != otherIdentityKey {
				otherShard.PaillierPublicKeys.Put(identityKey, paillierPublicKey)
				encrypt, _, err := paillierPublicKey.Encrypt(shard.SigningKeyShare.Share.BigInt())
				if err != nil {
					return nil, errs.WrapFailed(err, "cannot encrypt share with paillier")
				}
				otherShard.PaillierEncryptedShares.Put(identityKey, encrypt)
			}
		}
	}

	err = verifyShards(cohortConfig, shards, ecdsaPrivateKey)
	if err != nil {
		return nil, errs.NewVerificationFailed("failed to verify shards")
	}

	return shards, nil
}
