package trusted_dealer

import (
	"crypto/ecdsa"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/feldman"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/trusted_dealer"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
)

const (
	// This is the `p` and `q` prime bit length which makes Paillier modulus to be 2048 bits long.
	// It allows us to make either two homomorphic multiplications (being repetitive homomorphic additions)
	// or one homomorphic multiplication with a bunch of homomorphic additions
	// for curves that have up to 512 bits long subgroup order.
	paillierPrimeBitLength = 1024
)

func Keygen(protocol types.ThresholdSignatureProtocol, prng io.Reader) (ds.Map[types.IdentityKey, *lindell17.Shard], error) {
	if err := types.ValidateThresholdSignatureProtocolConfig(protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not validate protocol config")
	}

	curve := protocol.Curve()
	if curve.Name() != k256.Name && curve.Name() != p256.Name {
		return nil, errs.NewArgument("curve should be K256 or P256 where as it is %s", protocol.Curve().Name())
	}

	eCurve, err := curveutils.ToGoEllipticCurve(curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert krypton curve to go curve")
	}

	ecdsaPrivateKey, err := ecdsa.GenerateKey(eCurve, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate ECDSA private key")
	}

	privateKey := curve.ScalarField().Element().SetNat(new(saferith.Nat).SetBig(ecdsaPrivateKey.D, curve.Order().BitLen()))
	signingKeyShares, partialPublicKeys, err := trusted_dealer.Deal(protocol, privateKey, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not deal shares")
	}

	shards := hashmap.NewHashableHashMap[types.IdentityKey, *lindell17.Shard]()
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	for _, identityKey := range sharingConfig.Iter() {
		sks, exists := signingKeyShares.Get(identityKey)
		if !exists {
			return nil, errs.NewFailed("signing key share is missing")
		}
		ppk, exists := partialPublicKeys.Get(identityKey)
		if !exists {
			return nil, errs.NewFailed("signing key share is missing")
		}

		shards.Put(identityKey, &lindell17.Shard{
			SigningKeyShare:         sks,
			PublicKeyShares:         ppk,
			PaillierPublicKeys:      hashmap.NewComparableHashMap[types.SharingID, *paillier.PublicKey](),
			PaillierEncryptedShares: hashmap.NewComparableHashMap[types.SharingID, *paillier.CipherText](),
		})
	}

	// generate Paillier key pairs and encrypt share
	for i, identityKey := range sharingConfig.Iter() {
		sharingId, exists := sharingConfig.Reverse().Get(identityKey)
		if !exists {
			return nil, errs.NewMissing("sharing id of %s not found in sharing config", identityKey.String())
		}
		paillierPublicKey, paillierSecretKey, err := paillier.KeyGen(paillierPrimeBitLength, prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot generate paillier keys")
		}
		thisShard, exists := shards.Get(identityKey)
		if !exists {
			return nil, errs.NewMissing("couldn't find shard for sharing id %d", i)
		}
		thisShard.PaillierSecretKey = paillierSecretKey
		for j, value := range sharingConfig.Iter() {
			otherIdentityKey := value
			if identityKey.Equal(otherIdentityKey) {
				continue
			}
			otherShard, exists := shards.Get(otherIdentityKey)
			if !exists {
				return nil, errs.NewMissing("shard for sharing id %d is missing", j)
			}
			ct, _, err := paillierSecretKey.Encrypt(thisShard.SigningKeyShare.Share.Nat(), prng)
			if err != nil {
				return nil, errs.WrapFailed(err, "couldn't encrypt share of %d for %d", i, j)
			}
			otherShard.PaillierEncryptedShares.Put(sharingId, ct)
			otherShard.PaillierPublicKeys.Put(sharingId, paillierPublicKey)
		}
	}

	if err := validateShards(protocol, shards, ecdsaPrivateKey); err != nil {
		return nil, errs.WrapValidation(err, "failed to validate shards")
	}

	return shards, nil
}

func validateShards(protocol types.ThresholdSignatureProtocol, shards ds.Map[types.IdentityKey, *lindell17.Shard], ecdsaPrivateKey *ecdsa.PrivateKey) error {
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())

	for id, shard := range shards.Iter() {
		if err := shard.Validate(protocol, id.(types.IdentityKey), true); err != nil {
			return errs.WrapValidation(err, "shard for id %x", id)
		}
	}

	// verify private key
	feldmanShares := make([]*feldman.Share, shards.Size())
	for i := range feldmanShares {
		sharingId := types.SharingID(i + 1)
		identity, exists := sharingConfig.Get(sharingId)
		if !exists {
			return errs.NewMissing("could not find identity for sharing id %d", sharingId)
		}
		thisShard, exists := shards.Get(identity)
		if !exists {
			return errs.NewMissing("couldn't find shard for sharing id %d", sharingId)
		}
		feldmanShares[i] = &feldman.Share{
			Id:    uint(sharingId),
			Value: thisShard.SigningKeyShare.Share,
		}
	}
	dealer, err := feldman.NewDealer(protocol.Threshold(), protocol.TotalParties(), protocol.Curve())
	if err != nil {
		return errs.WrapFailed(err, "cannot create Feldman dealer")
	}
	recoveredPrivateKey, err := dealer.Combine(feldmanShares...)
	if err != nil {
		return errs.WrapFailed(err, "cannot combine Feldman shares")
	}
	if recoveredPrivateKey.Nat().Big().Cmp(ecdsaPrivateKey.D) != 0 {
		return errs.NewValue("recovered ECDSA private key is invalid")
	}

	// verify public key
	fieldOrder := protocol.Curve().BaseField().Order()
	recoveredPublicKey := protocol.Curve().ScalarBaseMult(recoveredPrivateKey)
	publicKey, err := protocol.Curve().NewPoint(
		protocol.Curve().BaseField().Element().SetNat(saferithUtils.NatFromBigMod(ecdsaPrivateKey.X, fieldOrder)),
		protocol.Curve().BaseField().Element().SetNat(saferithUtils.NatFromBigMod(ecdsaPrivateKey.Y, fieldOrder)),
	)
	if err != nil {
		return errs.WrapValue(err, "invalid ECDSA public key")
	}
	if !publicKey.Equal(recoveredPublicKey) {
		return errs.NewVerification("recovered ECDSA public key is invalid")
	}

	// verify Paillier encryption of shards
	for myIdentityKey, myShard := range shards.Iter() {
		mySharingId, exists := sharingConfig.Reverse().Get(myIdentityKey)
		if !exists {
			return errs.NewMissing("sharing id of %s not found in sharing config", myIdentityKey.String())
		}
		myShare := myShard.SigningKeyShare.Share.Nat()
		myPaillierPrivateKey := myShard.PaillierSecretKey
		for _, value := range shards.Iter() {
			theirShard := value
			if myShard.PaillierSecretKey.N.Eq(theirShard.PaillierSecretKey.N) == 0 {
				theirEncryptedShare, exists := theirShard.PaillierEncryptedShares.Get(mySharingId)
				if !exists {
					return errs.NewMissing("their encrypted share did not exist")
				}
				decryptor, err := paillier.NewDecryptor(myPaillierPrivateKey)
				if err != nil {
					return errs.WrapFailed(err, "cannot create paillier decryptor")
				}
				theirDecryptedShare, err := decryptor.Decrypt(theirEncryptedShare)
				if err != nil {
					return errs.WrapFailed(err, "cannot verify encrypted share")
				}
				if theirDecryptedShare.Eq(myShare) == 0 {
					return errs.NewVerification("cannot decrypt encrypted share")
				}
			}
		}
	}

	return nil
}
