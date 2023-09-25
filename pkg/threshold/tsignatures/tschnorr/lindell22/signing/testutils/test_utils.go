package testutils

import (
	crand "crypto/rand"

	"github.com/pkg/errors"

	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/signing"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

func MakeParticipants(sid []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, shards map[types.IdentityHash]*lindell22.Shard, allTranscripts []transcripts.Transcript, taproot bool) (participants []*signing.Cosigner, err error) {
	if len(identities) < cohortConfig.Protocol.Threshold {
		return nil, errors.Errorf("invalid number of identities %d != %d", len(identities), cohortConfig.Protocol.Threshold)
	}

	prng := crand.Reader
	participants = make([]*signing.Cosigner, cohortConfig.Protocol.Threshold)
	for i, identity := range identities {
		if !cohortConfig.IsInCohort(identity) {
			return nil, errors.New("invalid identity")
		}
		participants[i], err = signing.NewCosigner(identity, sid, hashset.NewHashSet(identities), shards[identity.Hash()], cohortConfig, allTranscripts[i], taproot, prng)
		if err != nil {
			return nil, err
		}
	}

	return participants, nil
}

func DoRound1(participants []*signing.Cosigner) (round2Inputs []map[types.IdentityHash]*signing.Round1Broadcast, err error) {
	round1Outputs := make([]*signing.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1Outputs[i], err = participant.Round1()
		if err != nil {
			return nil, err
		}
	}

	round2Inputs = make([]map[types.IdentityHash]*signing.Round1Broadcast, len(participants))
	for i := range participants {
		round2Inputs[i] = make(map[types.IdentityHash]*signing.Round1Broadcast)
		for j := range participants {
			round2Inputs[i][participants[j].GetIdentityKey().Hash()] = round1Outputs[j]
		}
	}

	return round2Inputs, nil
}

func DoRound2(participants []*signing.Cosigner, round2Inputs []map[types.IdentityHash]*signing.Round1Broadcast) (round3Inputs []map[types.IdentityHash]*signing.Round2Broadcast, err error) {
	round2Outputs := make([]*signing.Round2Broadcast, len(participants))
	for i, participant := range participants {
		round2Outputs[i], err = participant.Round2(round2Inputs[i])
		if err != nil {
			return nil, err
		}
	}

	round3Inputs = make([]map[types.IdentityHash]*signing.Round2Broadcast, len(participants))
	for i := range participants {
		round3Inputs[i] = make(map[types.IdentityHash]*signing.Round2Broadcast)
		for j := range participants {
			round3Inputs[i][participants[j].GetIdentityKey().Hash()] = round2Outputs[j]
		}
	}

	return round3Inputs, nil
}

func DoRound3(participants []*signing.Cosigner, round3Inputs []map[types.IdentityHash]*signing.Round2Broadcast, message []byte) (partialSignatures []*lindell22.PartialSignature, err error) {
	partialSignatures = make([]*lindell22.PartialSignature, len(participants))
	for i, participant := range participants {
		partialSignatures[i], err = participant.Round3(round3Inputs[i], message)
		if err != nil {
			return nil, err
		}
	}

	return partialSignatures, nil
}

func DoInteractiveSigning(participants []*signing.Cosigner, message []byte) (partialSignatures []*lindell22.PartialSignature, err error) {
	r2i, err := DoRound1(participants)
	if err != nil {
		return nil, err
	}

	r3i, err := DoRound2(participants, r2i)
	if err != nil {
		return nil, err
	}

	return DoRound3(participants, r3i, message)
}
