package testutils

import (
	crand "crypto/rand"
	"crypto/sha256"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	gennaroTestutils "github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/gennaro/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/keygen/trusted_dealer"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/signing"
)

func MakeSigningParticipants[K bls.KeySubGroup, S bls.SignatureSubGroup](uniqueSessionId []byte, protocol types.ThresholdSignatureProtocol, identities []types.IdentityKey, shards ds.Map[types.IdentityKey, *boldyreva02.Shard[K]], scheme bls.RogueKeyPrevention) (participants []*signing.Cosigner[K, S], err error) {
	if len(identities) < int(protocol.Threshold()) {
		return nil, errs.NewLength("invalid number of identities %d != %d", len(identities), protocol.Threshold())
	}

	participants = make([]*signing.Cosigner[K, S], len(identities))
	for i, identity := range identities {
		if !protocol.Participants().Contains(identity) {
			return nil, errs.NewMissing("protocol config is missing identity")
		}
		thisShard, exists := shards.Get(identity)
		if !exists {
			return nil, errs.NewMissing("shard")
		}
		participants[i], err = signing.NewCosigner[K, S](uniqueSessionId, identity.(types.AuthKey), scheme, hashset.NewHashableHashSet(identities...), thisShard, protocol, nil)
		if err != nil {
			return nil, errs.WrapFailed(err, "Could not construct participant")
		}
	}

	return participants, nil
}

func ProducePartialSignature[K bls.KeySubGroup, S bls.SignatureSubGroup](participants []*signing.Cosigner[K, S], message []byte, scheme bls.RogueKeyPrevention) (partialSignatures []*boldyreva02.PartialSignature[S], err error) {
	partialSignatures = make([]*boldyreva02.PartialSignature[S], len(participants))
	for i := range participants {
		partialSignatures[i], err = participants[i].ProducePartialSignature(message)
		if err != nil {
			return nil, errs.WrapFailed(err, "Could not produce partial signature")
		}
	}
	return partialSignatures, nil
}

func MapPartialSignatures[S bls.SignatureSubGroup](identities []types.IdentityKey, partialSignatures []*boldyreva02.PartialSignature[S]) types.RoundMessages[*boldyreva02.PartialSignature[S]] {
	result := types.NewRoundMessages[*boldyreva02.PartialSignature[S]]()
	for i, identity := range identities {
		result.Put(identity, partialSignatures[i])
	}
	return result
}

func SigningRoundTrip[K bls.KeySubGroup, S bls.SignatureSubGroup](threshold, n int, scheme bls.RogueKeyPrevention) error {
	hashFunc := sha256.New
	message := []byte("messi > ronaldo")
	sid := []byte("sessionId")

	keysSubGroup := bls12381.GetSourceSubGroup[K]()

	cipherSuite, err := ttu.MakeSignatureProtocol(keysSubGroup, hashFunc)
	if err != nil {
		return errs.WrapFailed(err, "could not make cipher suite")
	}

	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	if err != nil {
		return errs.WrapFailed(err, "Could not make test identities")
	}

	protocolConfig, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, threshold, identities)
	if err != nil {
		return errs.WrapFailed(err, "Could not make protocol config")
	}

	shards, err := trusted_dealer.Keygen[K](protocolConfig, crand.Reader)
	if err != nil {
		return err
	}

	aliceShard, exists := shards.Get(identities[0])
	if !exists {
		return errs.NewMissing("0th shard")
	}
	publicKeyShares := aliceShard.PublicKeyShares
	publicKey := publicKeyShares.PublicKey

	participants, err := MakeSigningParticipants[K, S](sid, protocolConfig, identities, shards, scheme)
	if err != nil {
		return err
	}

	partialSignatures, err := ProducePartialSignature(participants, message, scheme)
	if err != nil {
		return err
	}

	sharingConfig := types.DeriveSharingConfig(protocolConfig.Participants())
	aggregatorInput := MapPartialSignatures(identities, partialSignatures)
	signature, signaturePOP, err := signing.Aggregate(sharingConfig, publicKeyShares, aggregatorInput, message, scheme)
	if err != nil {
		return errs.WrapFailed(err, "Could not aggregate partial signatures")
	}

	err = bls.Verify(publicKey, signature, message, signaturePOP, scheme, nil)
	if err != nil {
		return errs.WrapVerification(err, "Could not verify signature")
	}
	return nil
}

func SigningWithDkg[K bls.KeySubGroup, S bls.SignatureSubGroup](threshold, n int, scheme bls.RogueKeyPrevention) error {
	hashFunc := sha256.New
	message := []byte("messi > ronaldo")
	sid := []byte("sessionId")

	keysSubGroup := bls12381.GetSourceSubGroup[K]()

	signatureProtocol, err := ttu.MakeSignatureProtocol(keysSubGroup, hashFunc)
	if err != nil {
		return errs.WrapFailed(err, "could not make cipher suite")
	}

	identities, err := ttu.MakeTestIdentities(signatureProtocol, n)
	if err != nil {
		return errs.WrapFailed(err, "Could not make test identities")
	}

	thresholdSignatureProtocol, err := ttu.MakeThresholdSignatureProtocol(signatureProtocol, identities, threshold, identities)
	if err != nil {
		return errs.WrapFailed(err, "Could not make protocol config")
	}

	signingKeyShares, partialPublicKeys, err := gennaroTestutils.RunDKG(sid, thresholdSignatureProtocol, identities)
	if err != nil {
		return errs.WrapFailed(err, "could not run JK-DKG")
	}

	shards := hashmap.NewHashableHashMap[types.IdentityKey, *boldyreva02.Shard[K]]()
	for i, id := range identities {
		shard, err := boldyreva02.NewShard[K](thresholdSignatureProtocol, signingKeyShares[i], partialPublicKeys[i])
		if err != nil {
			return errs.WrapFailed(err, "could not create a share")
		}
		shards.Put(id, shard)
	}

	aliceShard, exists := shards.Get(identities[0])
	if !exists {
		return errs.NewMissing("0th shard")
	}
	publicKeyShares := aliceShard.PublicKeyShares
	publicKey := publicKeyShares.PublicKey

	participants, err := MakeSigningParticipants[K, S](sid, thresholdSignatureProtocol, identities, shards, scheme)
	if err != nil {
		return err
	}

	partialSignatures, err := ProducePartialSignature(participants, message, scheme)
	if err != nil {
		return err
	}

	sharingConfig := types.DeriveSharingConfig(thresholdSignatureProtocol.Participants())
	aggregatorInput := MapPartialSignatures(identities, partialSignatures)
	signature, signaturePOP, err := signing.Aggregate(sharingConfig, publicKeyShares, aggregatorInput, message, scheme)
	if err != nil {
		return errs.WrapFailed(err, "Could not aggregate partial signatures")
	}
	if err != nil {
		return errs.WrapFailed(err, "Could not aggregate partial signatures")
	}

	err = bls.Verify(publicKey, signature, message, signaturePOP, scheme, nil)
	if err != nil {
		return errs.WrapVerification(err, "Could not verify signature")
	}
	return nil
}
