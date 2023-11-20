package testutils

import (
	crand "crypto/rand"
	"crypto/sha256"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow/keygen/trusted_dealer"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow/signing"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow/signing/aggregation"
)

func MakeSigningParticipants(uniqueSessionId []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, shards map[types.IdentityHash]*glow.Shard) (participants []*signing.Cosigner, err error) {
	if len(identities) < cohortConfig.Protocol.Threshold {
		return nil, errs.NewInvalidLength("invalid number of identities %d != %d", len(identities), cohortConfig.Protocol.Threshold)
	}

	participants = make([]*signing.Cosigner, len(identities))
	for i, identity := range identities {
		if !cohortConfig.IsInCohort(identity) {
			return nil, errs.NewMissing("invalid identity")
		}
		participants[i], err = signing.NewCosigner(uniqueSessionId, identity.(integration.AuthKey), hashset.NewHashSet(identities), shards[identity.Hash()], cohortConfig, nil, crand.Reader)
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

func MapPartialSignatures(identities []integration.IdentityKey, partialSignatures []*glow.PartialSignature) map[types.IdentityHash]*glow.PartialSignature {
	result := make(map[types.IdentityHash]*glow.PartialSignature)
	for i, identity := range identities {
		result[identity.Hash()] = partialSignatures[i]
	}
	return result
}

func SigningRoundTrip(threshold, n int) error {
	hashFunc := sha256.New
	message := []byte("messi > ronaldo")
	sid := []byte("sessionId")

	cipherSuite := &integration.CipherSuite{
		Curve: bls12381.NewG1(),
		Hash:  hashFunc,
	}

	identities, err := integration_testutils.MakeTestIdentities(cipherSuite, n)
	if err != nil {
		return errs.WrapFailed(err, "could not make test identities")
	}

	cohort, err := integration_testutils.MakeCohortProtocol(cipherSuite, protocols.BLS, identities, threshold, identities)
	if err != nil {
		return errs.WrapFailed(err, "could not make cohort protocol")
	}

	shards, err := trusted_dealer.Keygen(cohort, crand.Reader)
	if err != nil {
		return errs.WrapFailed(err, "could not run trusted dealer keygen")
	}

	publicKeyShares := shards[identities[0].Hash()].PublicKeyShares
	publicKey := publicKeyShares.PublicKey

	participants, err := MakeSigningParticipants(sid, cohort, identities, shards)
	if err != nil {
		return errs.WrapFailed(err, "could not make signing participants")
	}

	partialSignatures, err := ProducePartialSignature(participants, message)
	if err != nil {
		return errs.WrapFailed(err, "could not produce partial signatures")
	}

	aggregatorInput := MapPartialSignatures(identities, partialSignatures)

	agg, err := aggregation.NewAggregator(sid, shards[identities[0].Hash()].PublicKeyShares, cohort)
	if err != nil {
		return errs.WrapFailed(err, "could not make aggregator")
	}

	signature, err := agg.Aggregate(aggregatorInput, message)
	if err != nil {
		return errs.WrapFailed(err, "could not aggregate partial signatures")
	}

	err = bls.Verify(publicKey, signature, message, nil, bls.Basic, nil)
	if err != nil {
		return errs.WrapVerificationFailed(err, "could not verify signature")
	}
	return nil
}
