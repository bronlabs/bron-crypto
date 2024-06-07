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
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	jf_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/jf/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow/keygen/trusted_dealer"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow/signing"
)

func MakeSigningParticipants(uniqueSessionId []byte, protocol types.ThresholdSignatureProtocol, identities []types.IdentityKey, shards ds.Map[types.IdentityKey, *glow.Shard]) (participants []*signing.Cosigner, err error) {
	if len(identities) < int(protocol.Threshold()) {
		return nil, errs.NewLength("invalid number of identities %d != %d", len(identities), protocol.Threshold())
	}

	participants = make([]*signing.Cosigner, len(identities))
	for i, identity := range identities {
		if !protocol.Participants().Contains(identity) {
			return nil, errs.NewMissing("invalid identity")
		}
		thisShard, exists := shards.Get(identity)
		if !exists {
			return nil, errs.NewMissing("shard")
		}
		participants[i], err = signing.NewCosigner(uniqueSessionId, identity.(types.AuthKey), hashset.NewHashableHashSet(identities...), thisShard, protocol, nil, crand.Reader)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
	}

	return participants, nil
}

func ProducePartialSignature(participants []*signing.Cosigner, message []byte) (partialSignatures []*glow.PartialSignature, err error) {
	partialSignatures = make([]*glow.PartialSignature, len(participants))
	for i := range participants {
		partialSignatures[i], err = participants[i].ProducePartialSignature(message)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not produce glow20 partial signature")
		}
	}
	return partialSignatures, nil
}

func MapPartialSignatures(identities []types.IdentityKey, partialSignatures []*glow.PartialSignature) network.RoundMessages[types.ThresholdProtocol, *glow.PartialSignature] {
	result := network.NewRoundMessages[types.ThresholdProtocol, *glow.PartialSignature]()
	for i, identity := range identities {
		result.Put(identity, partialSignatures[i])
	}
	return result
}

func SigningRoundTrip(threshold, n int) error {
	hashFunc := sha256.New
	message := []byte("messi > ronaldo")
	sid := []byte("sessionId")

	cipherSuite, err := ttu.MakeSigningSuite(bls12381.NewG1(), hashFunc)
	if err != nil {
		return errs.WrapFailed(err, "could not make ciphersuite")
	}

	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	if err != nil {
		return errs.WrapFailed(err, "could not make test identities")
	}

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, threshold, identities)
	if err != nil {
		return errs.WrapFailed(err, "could not make protocol config")
	}

	shards, err := trusted_dealer.Keygen(protocol, crand.Reader)
	if err != nil {
		return errs.WrapFailed(err, "could not run trusted dealer keygen")
	}

	aliceShard, exists := shards.Get(identities[0])
	if !exists {
		return errs.NewMissing("0th shard")
	}
	publicKeyShares := aliceShard.PublicKeyShares
	publicKey := publicKeyShares.PublicKey

	participants, err := MakeSigningParticipants(sid, protocol, identities, shards)
	if err != nil {
		return errs.WrapFailed(err, "could not make signing participants")
	}

	partialSignatures, err := ProducePartialSignature(participants, message)
	if err != nil {
		return errs.WrapFailed(err, "could not produce partial signatures")
	}

	aggregatorInput := MapPartialSignatures(identities, partialSignatures)

	signature, err := signing.Aggregate(publicKeyShares, protocol, aggregatorInput, message)
	if err != nil {
		return errs.WrapFailed(err, "could not aggregate partial signatures")
	}

	err = bls.Verify(publicKey, signature, message, nil, bls.Basic, nil)
	if err != nil {
		return errs.WrapVerification(err, "could not verify signature")
	}
	return nil
}

func SigningWithDkg(threshold, n int) error {
	hashFunc := sha256.New
	message := []byte("messi > ronaldo")
	sid := []byte("sessionId")

	cipherSuite, err := ttu.MakeSigningSuite(bls12381.NewG1(), hashFunc)
	if err != nil {
		return errs.WrapFailed(err, "could not make ciphersuite")
	}

	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	if err != nil {
		return errs.WrapFailed(err, "could not make test identities")
	}

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, threshold, identities)
	if err != nil {
		return errs.WrapFailed(err, "could not make protocol config")
	}

	signingKeyShares, partialPublicKeys, err := jf_testutils.RunDKG(sid, protocol, identities)
	if err != nil {
		return errs.WrapFailed(err, "could not run JK-DKG")
	}

	shards := hashmap.NewHashableHashMap[types.IdentityKey, *glow.Shard]()
	for i, id := range identities {
		shard, err := glow.NewShard(protocol, signingKeyShares[i], partialPublicKeys[i])
		if err != nil {
			return errs.WrapFailed(err, "invalid share")
		}
		shards.Put(id, shard)
	}

	participants, err := MakeSigningParticipants(sid, protocol, identities, shards)
	if err != nil {
		return errs.WrapFailed(err, "could not make signing participants")
	}

	partialSignatures, err := ProducePartialSignature(participants, message)
	if err != nil {
		return errs.WrapFailed(err, "could not produce partial signatures")
	}

	aggregatorInput := MapPartialSignatures(identities, partialSignatures)

	aliceShard, _ := shards.Get(identities[0])

	signature, err := signing.Aggregate(aliceShard.PublicKeyShares, protocol, aggregatorInput, message)
	if err != nil {
		return errs.WrapFailed(err, "could not aggregate partial signatures")
	}

	err = bls.Verify(aliceShard.SigningKeyShare.PublicKey, signature, message, nil, bls.Basic, nil)
	if err != nil {
		return errs.WrapVerification(err, "could not verify signature")
	}
	return nil
}
