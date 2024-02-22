package trusted_dealer

import (
	"crypto/ecdsa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/trusted_dealer"
	"io"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/feldman"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

const (
	// This is the `p` and `q` prime bit length which makes Paillier modulus to be 2048 bits long.
	// It allows us to make either two homomorphic multiplications (being repetitive homomorphic additions)
	// or one homomorphic multiplication with a bunch of homomorphic additions
	// for curves that have up to 512 bits long subgroup order.
	paillierPrimeBitLength = 1024
)

func Keygen(protocol types.ThresholdSignatureProtocol, prng io.Reader) (ds.HashMap[types.IdentityKey, *lindell17.Shard], error) {
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

	privateKey := curve.Scalar().SetNat(new(saferith.Nat).SetBig(ecdsaPrivateKey.D, curve.SubGroupOrder().BitLen()))
	signingKeyShares, partialPublicKeys, err := trusted_dealer.Deal(protocol, privateKey, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not deal shares")
	}

	shards := hashmap.NewHashableHashMap[types.IdentityKey, *lindell17.Shard]()
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	for pair := range sharingConfig.Iter() {
		identityKey := pair.Right

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
			PaillierPublicKeys:      hashmap.NewHashableHashMap[types.IdentityKey, *paillier.PublicKey](),
			PaillierEncryptedShares: hashmap.NewHashableHashMap[types.IdentityKey, *paillier.CipherText](),
		})
	}

	// generate Paillier key pairs and encrypt share
	for pair := range sharingConfig.Iter() {
		i := pair.Left
		identityKey := pair.Right
		paillierPublicKey, paillierSecretKey, err := paillier.NewKeys(paillierPrimeBitLength)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot generate paillier keys")
		}
		thisShard, exists := shards.Get(identityKey)
		if !exists {
			return nil, errs.NewMissing("couldn't find shard for sharing id %d", i)
		}
		thisShard.PaillierSecretKey = paillierSecretKey
		for pair := range sharingConfig.Iter() {
			j := pair.Left
			otherIdentityKey := pair.Right
			if identityKey.Equal(otherIdentityKey) {
				continue
			}
			otherShard, exists := shards.Get(otherIdentityKey)
			if !exists {
				return nil, errs.NewMissing("shard for sharing id %d is missing", j)
			}
			ct, _, err := paillierPublicKey.Encrypt(thisShard.SigningKeyShare.Share.Nat())
			if err != nil {
				return nil, errs.WrapFailed(err, "couldn't encrypt share of %d for %d", i, j)
			}
			otherShard.PaillierEncryptedShares.Put(identityKey, ct)
			otherShard.PaillierPublicKeys.Put(identityKey, paillierPublicKey)
		}
	}

	if err := validateShards(protocol, shards, ecdsaPrivateKey); err != nil {
		return nil, errs.WrapValidation(err, "failed to vlidate shards")
	}

	return shards, nil
}

func validateShards(protocol types.ThresholdSignatureProtocol, shards ds.HashMap[types.IdentityKey, *lindell17.Shard], ecdsaPrivateKey *ecdsa.PrivateKey) error {
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())

	for pair := range shards.Iter() {
		id := pair.Key
		shard := pair.Value
		if err := shard.Validate(protocol, id.(types.IdentityKey), true); err != nil {
			return errs.WrapValidation(err, "shard for id %x", id)
		}
	}

	// verify private key
	feldmanShares := make([]*feldman.Share, shards.Size())
	for i := range feldmanShares {
		sharingId := types.SharingID(i + 1)
		identity, exists := sharingConfig.LookUpLeft(sharingId)
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
		protocol.Curve().BaseField().Element().SetNat(utils.NatFromBig(ecdsaPrivateKey.X, fieldOrder)),
		protocol.Curve().BaseField().Element().SetNat(utils.NatFromBig(ecdsaPrivateKey.Y, fieldOrder)),
	)
	if err != nil {
		return errs.WrapValue(err, "invalid ECDSA public key")
	}
	if !publicKey.Equal(recoveredPublicKey) {
		return errs.NewVerification("recovered ECDSA public key is invalid")
	}

	// verify Paillier encryption of shards
	for pair := range shards.Iter() {
		myIdentityKey := pair.Key
		myShard := pair.Value
		myShare := myShard.SigningKeyShare.Share.Nat()
		myPaillierPrivateKey := myShard.PaillierSecretKey
		for pair := range shards.Iter() {
			theirShard := pair.Value
			if myShard.PaillierSecretKey.N.Nat().Eq(theirShard.PaillierSecretKey.N.Nat()) == 0 && myShard.PaillierSecretKey.N2.Nat().Eq(theirShard.PaillierSecretKey.N2.Nat()) == 0 {
				theirEncryptedShare, exists := theirShard.PaillierEncryptedShares.Get(myIdentityKey)
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
