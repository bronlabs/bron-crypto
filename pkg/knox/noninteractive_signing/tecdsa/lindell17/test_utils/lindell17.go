package test_utils

import (
	crand "crypto/rand"

	"github.com/copperexchange/knox-primitives/pkg/base/integration"
	"github.com/copperexchange/knox-primitives/pkg/base/integration/helper_types"
	lindell17_noninteractive_signing "github.com/copperexchange/knox-primitives/pkg/knox/noninteractive_signing/tecdsa/lindell17"
	"github.com/copperexchange/knox-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

func MakeTranscripts(label string, identities []integration.IdentityKey) []transcripts.Transcript {
	allTranscripts := make([]transcripts.Transcript, len(identities))
	for i := range identities {
		allTranscripts[i] = hagrid.NewTranscript(label)
	}

	return allTranscripts
}

func MakePreGenParticipants(tau int, identities []integration.IdentityKey, sid []byte, cohort *integration.CohortConfig, allTranscripts []transcripts.Transcript) (participants []*lindell17_noninteractive_signing.PreGenParticipant, err error) {
	prng := crand.Reader
	parties := make([]*lindell17_noninteractive_signing.PreGenParticipant, len(identities))
	for i := range identities {
		parties[i], err = lindell17_noninteractive_signing.NewPreGenParticipant(sid, allTranscripts[i], identities[i], cohort, tau, prng)
		if err != nil {
			return nil, err
		}
	}

	return parties, nil
}

func DoPreGenRound1(participants []*lindell17_noninteractive_signing.PreGenParticipant) (output []map[helper_types.IdentityHash]*lindell17_noninteractive_signing.Round1Broadcast, err error) {
	result := make([]map[helper_types.IdentityHash]*lindell17_noninteractive_signing.Round1Broadcast, len(participants))
	for i := range participants {
		result[i] = make(map[helper_types.IdentityHash]*lindell17_noninteractive_signing.Round1Broadcast)
	}

	for i, party := range participants {
		out, err := participants[i].Round1()
		if err != nil {
			return nil, err
		}
		for j := range participants {
			if j != i {
				result[j][party.GetIdentityKey().Hash()] = out
			}
		}
	}

	return result, nil
}

func DoPreGenRound2(participants []*lindell17_noninteractive_signing.PreGenParticipant, input []map[helper_types.IdentityHash]*lindell17_noninteractive_signing.Round1Broadcast) (output []map[helper_types.IdentityHash]*lindell17_noninteractive_signing.Round2Broadcast, err error) {
	result := make([]map[helper_types.IdentityHash]*lindell17_noninteractive_signing.Round2Broadcast, len(participants))
	for i := range participants {
		result[i] = make(map[helper_types.IdentityHash]*lindell17_noninteractive_signing.Round2Broadcast)
	}

	for i, party := range participants {
		out, err := participants[i].Round2(input[i])
		if err != nil {
			return nil, err
		}
		for j := range participants {
			if j != i {
				result[j][party.GetIdentityKey().Hash()] = out
			}
		}
	}

	return result, nil
}

func DoPreGenRound3(participants []*lindell17_noninteractive_signing.PreGenParticipant, input []map[helper_types.IdentityHash]*lindell17_noninteractive_signing.Round2Broadcast) (output []*lindell17.PreSignatureBatch, err error) {
	result := make([]*lindell17.PreSignatureBatch, len(participants))

	for i := range participants {
		out, err := participants[i].Round3(input[i])
		if err != nil {
			return nil, err
		}
		result[i] = out
	}

	return result, nil
}

func DoLindell2017PreGen(participants []*lindell17_noninteractive_signing.PreGenParticipant) (output []*lindell17.PreSignatureBatch, err error) {
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
