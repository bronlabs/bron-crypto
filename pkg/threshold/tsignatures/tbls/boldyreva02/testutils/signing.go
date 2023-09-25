package testutils

import (
	"github.com/pkg/errors"

	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/signing"
)

func MakeSigningParticipants[K bls.KeySubGroup, S bls.SignatureSubGroup](uniqueSessionId []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, shards map[types.IdentityHash]*boldyreva02.Shard[K]) (participants []*signing.Cosigner[K, S], err error) {
	if len(identities) < cohortConfig.Protocol.Threshold {
		return nil, errors.Errorf("invalid number of identities %d != %d", len(identities), cohortConfig.Protocol.Threshold)
	}

	participants = make([]*signing.Cosigner[K, S], len(identities))
	for i, identity := range identities {
		if !cohortConfig.IsInCohort(identity) {
			return nil, errors.New("invalid identity")
		}
		participants[i], err = signing.NewCosigner[K, S](uniqueSessionId, identity, hashset.NewHashSet(identities), shards[identity.Hash()], cohortConfig, nil)
		if err != nil {
			return nil, err
		}
	}

	return participants, nil
}

func ProducePartialSignature[K bls.KeySubGroup, S bls.SignatureSubGroup](participants []*signing.Cosigner[K, S], message []byte) (partialSignatures []*boldyreva02.PartialSignature[S], err error) {
	partialSignatures = make([]*boldyreva02.PartialSignature[S], len(participants))
	for i := range participants {
		partialSignatures[i], err = participants[i].ProducePartialSignature(message)
		if err != nil {
			return nil, err
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
