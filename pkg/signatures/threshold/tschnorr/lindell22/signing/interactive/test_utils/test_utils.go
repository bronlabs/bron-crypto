package test_utils

import (
	crand "crypto/rand"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tschnorr/lindell22"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tschnorr/lindell22/signing/interactive"
	"github.com/copperexchange/crypto-primitives-go/pkg/transcript"
	"github.com/pkg/errors"
)

func MakeParticipants(sid []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, shards map[integration.IdentityKey]*threshold.SigningKeyShare, transcripts []transcript.Transcript) (participants []*interactive.Cosigner, err error) {
	if len(identities) < cohortConfig.Threshold {
		return nil, errors.Errorf("invalid number of identities %d != %d", len(identities), cohortConfig.Threshold)
	}

	prng := crand.Reader
	participants = make([]*interactive.Cosigner, cohortConfig.Threshold)
	for i, identity := range identities {
		if !cohortConfig.IsInCohort(identity) {
			return nil, errors.New("invalid identity")
		}
		participants[i], err = interactive.NewCosigner(identity, sid, identities, shards[identity], cohortConfig, transcripts[i], prng)
		if err != nil {
			return nil, err
		}
	}

	return participants, nil
}

func DoRound1(participants []*interactive.Cosigner) (round2Inputs []map[integration.IdentityKey]*interactive.Round1Broadcast, err error) {
	round1Outputs := make([]*interactive.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1Outputs[i], err = participant.Round1()
		if err != nil {
			return nil, err
		}
	}

	round2Inputs = make([]map[integration.IdentityKey]*interactive.Round1Broadcast, len(participants))
	for i := range participants {
		round2Inputs[i] = make(map[integration.IdentityKey]*interactive.Round1Broadcast)
		for j := range participants {
			round2Inputs[i][participants[j].GetIdentityKey()] = round1Outputs[j]
		}
	}

	return round2Inputs, nil
}

func DoRound2(participants []*interactive.Cosigner, round2Inputs []map[integration.IdentityKey]*interactive.Round1Broadcast) (round3Inputs []map[integration.IdentityKey]*interactive.Round2Broadcast, err error) {
	round2Outputs := make([]*interactive.Round2Broadcast, len(participants))
	for i, participant := range participants {
		round2Outputs[i], err = participant.Round2(round2Inputs[i])
		if err != nil {
			return nil, err
		}
	}

	round3Inputs = make([]map[integration.IdentityKey]*interactive.Round2Broadcast, len(participants))
	for i := range participants {
		round3Inputs[i] = make(map[integration.IdentityKey]*interactive.Round2Broadcast)
		for j := range participants {
			round3Inputs[i][participants[j].GetIdentityKey()] = round2Outputs[j]
		}
	}

	return round3Inputs, nil
}

func DoRound3(participants []*interactive.Cosigner, round3Inputs []map[integration.IdentityKey]*interactive.Round2Broadcast, message []byte) (partialSignatures []*lindell22.PartialSignature, err error) {
	partialSignatures = make([]*lindell22.PartialSignature, len(participants))
	for i, participant := range participants {
		partialSignatures[i], err = participant.Round3(round3Inputs[i], message)
		if err != nil {
			return nil, err
		}
	}

	return partialSignatures, nil
}

func DoInteractiveSigning(participants []*interactive.Cosigner, message []byte) (partialSignatures []*lindell22.PartialSignature, err error) {
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
