package testutils

import (
	crand "crypto/rand"
	"crypto/sha256"

	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/keygen/trusted_dealer"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/signing"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/signing/aggregation"
)

func MakeSigningParticipants[K bls.KeySubGroup, S bls.SignatureSubGroup](uniqueSessionId []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, shards map[types.IdentityHash]*boldyreva02.Shard[K]) (participants []*signing.Cosigner[K, S], err error) {
	if len(identities) < cohortConfig.Protocol.Threshold {
		return nil, errs.NewInvalidLength("invalid number of identities %d != %d", len(identities), cohortConfig.Protocol.Threshold)
	}

	participants = make([]*signing.Cosigner[K, S], len(identities))
	for i, identity := range identities {
		if !cohortConfig.IsInCohort(identity) {
			return nil, errs.NewMissing("cohort is missing identity")
		}
		participants[i], err = signing.NewCosigner[K, S](uniqueSessionId, identity, hashset.NewHashSet(identities), shards[identity.Hash()], cohortConfig, nil)
		if err != nil {
			return nil, errs.WrapFailed(err, "Could not construct participant")
		}
	}

	return participants, nil
}

func ProducePartialSignature[K bls.KeySubGroup, S bls.SignatureSubGroup](participants []*signing.Cosigner[K, S], message []byte) (partialSignatures []*boldyreva02.PartialSignature[S], err error) {
	partialSignatures = make([]*boldyreva02.PartialSignature[S], len(participants))
	for i := range participants {
		partialSignatures[i], err = participants[i].ProducePartialSignature(message)
		if err != nil {
			return nil, errs.WrapFailed(err, "Could not produce partial signature")
		}
	}
	return partialSignatures, nil
}

func MapPartialSignatures[S bls.SignatureSubGroup](identities []integration.IdentityKey, partialSignatures []*boldyreva02.PartialSignature[S]) map[types.IdentityHash]*boldyreva02.PartialSignature[S] {
	result := make(map[types.IdentityHash]*boldyreva02.PartialSignature[S])
	for i, identity := range identities {
		result[identity.Hash()] = partialSignatures[i]
	}
	return result
}

func SigningRoundTrip[K bls.KeySubGroup, S bls.SignatureSubGroup](threshold, n int) error {
	hashFunc := sha256.New
	message := []byte("messi > ronaldo")
	sid := []byte("sessionId")

	pointInK := new(K)
	keysSubGroup := (*pointInK).Curve()

	cipherSuite := &integration.CipherSuite{
		Curve: keysSubGroup,
		Hash:  hashFunc,
	}

	identities, err := integration_testutils.MakeTestIdentities(cipherSuite, n)
	if err != nil {
		return errs.WrapFailed(err, "Could not make test identities")
	}

	cohort, err := integration_testutils.MakeCohortProtocol(cipherSuite, protocols.BLS, identities, threshold, identities)
	if err != nil {
		return errs.WrapFailed(err, "Could not make cohort protocol")
	}

	shards, err := trusted_dealer.Keygen[K](cohort, crand.Reader)
	if err != nil {
		return err
	}

	publicKeyShares := shards[identities[0].Hash()].PublicKeyShares
	publicKey := publicKeyShares.PublicKey

	participants, err := MakeSigningParticipants[K, S](sid, cohort, identities, shards)
	if err != nil {
		return err
	}

	partialSignatures, err := ProducePartialSignature(participants, message)
	if err != nil {
		return err
	}

	aggregatorInput := MapPartialSignatures(identities, partialSignatures)

	agg, err := aggregation.NewAggregator[K, S](shards[identities[0].Hash()].PublicKeyShares, cohort)
	if err != nil {
		return err
	}

	signature, err := agg.Aggregate(aggregatorInput, message)
	if err != nil {
		return errs.WrapFailed(err, "Could not aggregate partial signatures")
	}

	err = bls.Verify(publicKey, signature, message, nil, bls.Basic, nil)
	if err != nil {
		return errs.WrapVerificationFailed(err, "Could not verify signature")
	}
	return nil
}
