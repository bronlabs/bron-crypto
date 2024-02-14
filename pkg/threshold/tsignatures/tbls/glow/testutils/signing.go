package testutils

import (
	crand "crypto/rand"
	"crypto/sha256"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow/keygen/trusted_dealer"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow/signing"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow/signing/aggregation"
)

func MakeSigningParticipants(uniqueSessionId []byte, protocol types.ThresholdSignatureProtocol, identities []types.IdentityKey, shards ds.HashMap[types.IdentityKey, *glow.Shard]) (participants []*signing.Cosigner, err error) {
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

func MapPartialSignatures(identities []types.IdentityKey, partialSignatures []*glow.PartialSignature) types.RoundMessages[*glow.PartialSignature] {
	result := types.NewRoundMessages[*glow.PartialSignature]()
	for i, identity := range identities {
		result.Put(identity, partialSignatures[i])
	}
	return result
}

func SigningRoundTrip(threshold, n int) error {
	hashFunc := sha256.New
	message := []byte("messi > ronaldo")
	sid := []byte("sessionId")

	cipherSuite, err := ttu.MakeSignatureProtocol(bls12381.NewG1(), hashFunc)
	if err != nil {
		return errs.WrapFailed(err, "could not make ciphersuite")
	}

	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	if err != nil {
		return errs.WrapFailed(err, "could not make test identities")
	}

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, threshold, identities)
	if err != nil {
		return errs.WrapFailed(err, "could not make cohort protocol")
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

	agg, err := aggregation.NewAggregator(sid, publicKeyShares, protocol)
	if err != nil {
		return errs.WrapFailed(err, "could not make aggregator")
	}

	signature, err := agg.Aggregate(aggregatorInput, message)
	if err != nil {
		return errs.WrapFailed(err, "could not aggregate partial signatures")
	}

	err = bls.Verify(publicKey, signature, message, nil, bls.Basic, nil)
	if err != nil {
		return errs.WrapVerification(err, "could not verify signature")
	}
	return nil
}
