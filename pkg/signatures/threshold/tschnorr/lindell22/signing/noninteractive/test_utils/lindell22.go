package test_utils

import (
	crand "crypto/rand"

	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/signing/noninteractive"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
)

func MakePreGenParticipants(tau int, identities []integration.IdentityKey, sid []byte, cohort *integration.CohortConfig, myTranscripts []transcripts.Transcript) (participants []*noninteractive.PreGenParticipant, err error) {
	prng := crand.Reader
	parties := make([]*noninteractive.PreGenParticipant, len(identities))
	for i := range identities {
		parties[i], err = noninteractive.NewPreGenParticipant(tau, identities[i], sid, cohort, myTranscripts[i], prng)
		if err != nil {
			return nil, err
		}
	}

	return parties, nil
}

func DoPreGenRound1(participants []*noninteractive.PreGenParticipant) (output []map[helper_types.IdentityHash]*noninteractive.Round1Broadcast, err error) {
	result := make([]map[helper_types.IdentityHash]*noninteractive.Round1Broadcast, len(participants))
	for i := range participants {
		result[i] = make(map[helper_types.IdentityHash]*noninteractive.Round1Broadcast)
	}

	for i, party := range participants {
		out, err := participants[i].Round1()
		if err != nil {
			return nil, err
		}
		for j := range participants {
			result[j][party.GetIdentityKey().Hash()] = out
		}
	}

	return result, nil
}

func DoPreGenRound2(participants []*noninteractive.PreGenParticipant, input []map[helper_types.IdentityHash]*noninteractive.Round1Broadcast) (output []map[helper_types.IdentityHash]*noninteractive.Round2Broadcast, err error) {
	result := make([]map[helper_types.IdentityHash]*noninteractive.Round2Broadcast, len(participants))
	for i := range participants {
		result[i] = make(map[helper_types.IdentityHash]*noninteractive.Round2Broadcast)
	}

	for i, party := range participants {
		out, err := participants[i].Round2(input[i])
		if err != nil {
			return nil, err
		}
		for j := range participants {
			result[j][party.GetIdentityKey().Hash()] = out
		}
	}

	return result, nil
}

func DoPreGenRound3(participants []*noninteractive.PreGenParticipant, input []map[helper_types.IdentityHash]*noninteractive.Round2Broadcast) (output []*lindell22.PreSignatureBatch, err error) {
	result := make([]*lindell22.PreSignatureBatch, len(participants))

	for i := range participants {
		out, err := participants[i].Round3(input[i])
		if err != nil {
			return nil, err
		}
		result[i] = out
	}

	return result, nil
}

func DoLindell2022PreGen(participants []*noninteractive.PreGenParticipant) (output []*lindell22.PreSignatureBatch, err error) {
	r1, err := DoPreGenRound1(participants)
	if err != nil {
		return nil, err
	}
	r2, err := DoPreGenRound2(participants, r1)
	if err != nil {
		return nil, err
	}
	return DoPreGenRound3(participants, r2)
}
