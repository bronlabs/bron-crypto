package testutils

import (
	crand "crypto/rand"

	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/interactive_signing"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

func MakeParticipants(sid []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, shards map[types.IdentityHash]*lindell22.Shard, allTranscripts []transcripts.Transcript, taproot bool) (participants []*interactive_signing.Cosigner, err error) {
	if len(identities) < cohortConfig.Protocol.Threshold {
		return nil, errs.NewInvalidLength("invalid number of identities %d != %d", len(identities), cohortConfig.Protocol.Threshold)
	}

	prng := crand.Reader
	participants = make([]*interactive_signing.Cosigner, cohortConfig.Protocol.Threshold)
	for i, identity := range identities {
		if !cohortConfig.IsInCohort(identity) {
			return nil, errs.NewMissing("cohort is missing identity")
		}
		participants[i], err = interactive_signing.NewCosigner(identity.(integration.AuthKey), sid, hashset.NewHashSet(identities), shards[identity.Hash()], cohortConfig, allTranscripts[i], taproot, prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to create cosigner")
		}
	}

	return participants, nil
}

func DoRound1(participants []*interactive_signing.Cosigner) (round2BroadcastInputs []map[types.IdentityHash]*interactive_signing.Round1Broadcast, round2UnicastInputs []map[types.IdentityHash]*interactive_signing.Round1P2P, err error) {
	round1BroadcastOutputs := make([]*interactive_signing.Round1Broadcast, len(participants))
	round1UnicastOutputs := make([]map[types.IdentityHash]*interactive_signing.Round1P2P, len(participants))
	for i, participant := range participants {
		round1BroadcastOutputs[i], round1UnicastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "failed to do lindell22 round 1")
		}
	}

	round2BroadcastInputs = make([]map[types.IdentityHash]*interactive_signing.Round1Broadcast, len(participants))
	round2UnicastInputs = make([]map[types.IdentityHash]*interactive_signing.Round1P2P, len(participants))
	for i := range participants {
		round2BroadcastInputs[i] = make(map[types.IdentityHash]*interactive_signing.Round1Broadcast)
		round2UnicastInputs[i] = make(map[types.IdentityHash]*interactive_signing.Round1P2P)
		for j := range participants {
			if i == j {
				continue
			}
			round2BroadcastInputs[i][participants[j].GetAuthKey().Hash()] = round1BroadcastOutputs[j]
			round2UnicastInputs[i][participants[j].GetAuthKey().Hash()] = round1UnicastOutputs[j][participants[i].GetAuthKey().Hash()]
		}
	}

	return round2BroadcastInputs, round2UnicastInputs, nil
}

func DoRound2(participants []*interactive_signing.Cosigner, round2BroadcastInputs []map[types.IdentityHash]*interactive_signing.Round1Broadcast, round2UnicastInputs []map[types.IdentityHash]*interactive_signing.Round1P2P) (round3BroadcastInputs []map[types.IdentityHash]*interactive_signing.Round2Broadcast, round3UnicastInputs []map[types.IdentityHash]*interactive_signing.Round2P2P, err error) {
	round2BroadcastOutputs := make([]*interactive_signing.Round2Broadcast, len(participants))
	round2UnicastOutputs := make([]map[types.IdentityHash]*interactive_signing.Round2P2P, len(participants))
	for i, participant := range participants {
		round2BroadcastOutputs[i], round2UnicastOutputs[i], err = participant.Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "failed to do lindell22 round 2")
		}
	}

	round3BroadcastInputs = make([]map[types.IdentityHash]*interactive_signing.Round2Broadcast, len(participants))
	round3UnicastInputs = make([]map[types.IdentityHash]*interactive_signing.Round2P2P, len(participants))
	for i := range participants {
		round3BroadcastInputs[i] = make(map[types.IdentityHash]*interactive_signing.Round2Broadcast)
		round3UnicastInputs[i] = make(map[types.IdentityHash]*interactive_signing.Round2P2P)
		for j := range participants {
			if i == j {
				continue
			}
			round3BroadcastInputs[i][participants[j].GetAuthKey().Hash()] = round2BroadcastOutputs[j]
			round3UnicastInputs[i][participants[j].GetAuthKey().Hash()] = round2UnicastOutputs[j][participants[i].GetAuthKey().Hash()]
		}
	}

	return round3BroadcastInputs, round3UnicastInputs, nil
}

func DoRound3(participants []*interactive_signing.Cosigner, round3BroadcastInputs []map[types.IdentityHash]*interactive_signing.Round2Broadcast, round3UnicastInputs []map[types.IdentityHash]*interactive_signing.Round2P2P, message []byte) (partialSignatures []*lindell22.PartialSignature, err error) {
	partialSignatures = make([]*lindell22.PartialSignature, len(participants))
	for i, participant := range participants {
		partialSignatures[i], err = participant.Round3(round3BroadcastInputs[i], round3UnicastInputs[i], message)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to do lindell22 round 3")
		}
	}

	return partialSignatures, nil
}

func RunInteractiveSigning(participants []*interactive_signing.Cosigner, message []byte) (partialSignatures []*lindell22.PartialSignature, err error) {
	r2bi, r2ui, err := DoRound1(participants)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to do lindell22 round 1")
	}

	r3bi, r3ui, err := DoRound2(participants, r2bi, r2ui)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to do lindell22 round 2")
	}

	partialSignatures, err = DoRound3(participants, r3bi, r3ui, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to do lindell22 round 3")
	}
	return partialSignatures, nil
}
