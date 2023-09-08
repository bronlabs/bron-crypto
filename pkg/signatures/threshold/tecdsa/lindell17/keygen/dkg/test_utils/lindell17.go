package test_utils

import (
	crand "crypto/rand"
	agreeonrandom_test_utils "github.com/copperexchange/knox-primitives/pkg/agreeonrandom/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	gennaro_dkg_test_utils "github.com/copperexchange/knox-primitives/pkg/dkg/gennaro/test_utils"
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17"
	lindell17_dkg "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17/keygen/dkg"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/pkg/errors"
)

func MakeParticipants(sid []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, signingShares []*threshold.SigningKeyShare, publicKeyShares []*threshold.PublicKeyShares, allTranscripts []transcripts.Transcript, prngs []io.Reader) (participants []*lindell17_dkg.Participant, err error) {
	if len(identities) != cohortConfig.Protocol.TotalParties {
		return nil, errors.Errorf("invalid number of identities %d != %d", len(identities), cohortConfig.Protocol.TotalParties)
	}

	participants = make([]*lindell17_dkg.Participant, cohortConfig.Protocol.TotalParties)
	for i, identity := range identities {
		var prng io.Reader
		if prngs != nil && prngs[i] != nil {
			prng = prngs[i]
		} else {
			prng = crand.Reader
		}
		var transcript transcripts.Transcript
		if allTranscripts != nil && allTranscripts[i] != nil {
			transcript = allTranscripts[i]
		}

		if !cohortConfig.IsInCohort(identity) {
			return nil, errors.New("given test identity not in cohort (problem in tests?)")
		}
		participants[i], err = lindell17_dkg.NewBackupParticipant(identity, signingShares[i], publicKeyShares[i], cohortConfig, prng, sid, transcript)
	}

	return participants, nil
}

func DoDkgRound1(participants []*lindell17_dkg.Participant) (round1BroadcastOutputs []*lindell17_dkg.Round1Broadcast, err error) {
	round1BroadcastOutputs = make([]*lindell17_dkg.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1BroadcastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, err
		}
	}

	return round1BroadcastOutputs, nil
}

func MapDkgRound1OutputsToRound2Inputs(participants []*lindell17_dkg.Participant, round1BroadcastOutputs []*lindell17_dkg.Round1Broadcast) (round2BroadcastInputs []map[helper_types.IdentityHash]*lindell17_dkg.Round1Broadcast) {
	round2BroadcastInputs = make([]map[helper_types.IdentityHash]*lindell17_dkg.Round1Broadcast, len(participants))
	for i := range participants {
		round2BroadcastInputs[i] = make(map[helper_types.IdentityHash]*lindell17_dkg.Round1Broadcast)
		for j := range participants {
			if j != i {
				round2BroadcastInputs[i][participants[j].GetIdentityKey().Hash()] = round1BroadcastOutputs[j]
			}
		}
	}

	return round2BroadcastInputs
}

func DoDkgRound2(participants []*lindell17_dkg.Participant, round2BroadcastInputs []map[helper_types.IdentityHash]*lindell17_dkg.Round1Broadcast) (round2Outputs []*lindell17_dkg.Round2Broadcast, err error) {
	round2Outputs = make([]*lindell17_dkg.Round2Broadcast, len(participants))
	for i := range participants {
		round2Outputs[i], err = participants[i].Round2(round2BroadcastInputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round2Outputs, nil
}

func MapDkgRound2OutputsToRound3Inputs(participants []*lindell17_dkg.Participant, round2Outputs []*lindell17_dkg.Round2Broadcast) (round3Inputs []map[helper_types.IdentityHash]*lindell17_dkg.Round2Broadcast) {
	round3Inputs = make([]map[helper_types.IdentityHash]*lindell17_dkg.Round2Broadcast, len(participants))
	for i := range participants {
		round3Inputs[i] = make(map[helper_types.IdentityHash]*lindell17_dkg.Round2Broadcast)
		for j := range participants {
			if j != i {
				round3Inputs[i][participants[j].GetIdentityKey().Hash()] = round2Outputs[j]
			}
		}
	}

	return round3Inputs
}

func DoDkgRound3(participants []*lindell17_dkg.Participant, round3Inputs []map[helper_types.IdentityHash]*lindell17_dkg.Round2Broadcast) (round3Outputs []*lindell17_dkg.Round3Broadcast, err error) {
	round3Outputs = make([]*lindell17_dkg.Round3Broadcast, len(participants))
	for i := range participants {
		round3Outputs[i], err = participants[i].Round3(round3Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round3Outputs, nil
}

func MapDkgRound3OutputsToRound4Inputs(participants []*lindell17_dkg.Participant, round3Outputs []*lindell17_dkg.Round3Broadcast) (round4Inputs []map[helper_types.IdentityHash]*lindell17_dkg.Round3Broadcast) {
	round4Inputs = make([]map[helper_types.IdentityHash]*lindell17_dkg.Round3Broadcast, len(participants))
	for i := range participants {
		round4Inputs[i] = make(map[helper_types.IdentityHash]*lindell17_dkg.Round3Broadcast)
		for j := range participants {
			if j != i {
				round4Inputs[i][participants[j].GetIdentityKey().Hash()] = round3Outputs[j]
			}
		}
	}

	return round4Inputs
}

func DoDkgRound4(participants []*lindell17_dkg.Participant, round4Inputs []map[helper_types.IdentityHash]*lindell17_dkg.Round3Broadcast) (round4Unicast []map[helper_types.IdentityHash]*lindell17_dkg.Round4P2P, err error) {
	round4Outputs := make([]map[helper_types.IdentityHash]*lindell17_dkg.Round4P2P, len(participants))
	for i := range participants {
		round4Outputs[i], err = participants[i].Round4(round4Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round4Outputs, nil
}

func MapDkgRound4OutputsToRound5Inputs(participants []*lindell17_dkg.Participant, round4UnicastOutputs []map[helper_types.IdentityHash]*lindell17_dkg.Round4P2P) (round5UnicastInputs []map[helper_types.IdentityHash]*lindell17_dkg.Round4P2P) {
	round5UnicastInputs = make([]map[helper_types.IdentityHash]*lindell17_dkg.Round4P2P, len(participants))
	for i := range participants {
		round5UnicastInputs[i] = make(map[helper_types.IdentityHash]*lindell17_dkg.Round4P2P)
		for j := range participants {
			if j != i {
				round5UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round4UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}

	return round5UnicastInputs
}

func DoDkgRound5(participants []*lindell17_dkg.Participant, round5Inputs []map[helper_types.IdentityHash]*lindell17_dkg.Round4P2P) (round5Outputs []map[helper_types.IdentityHash]*lindell17_dkg.Round5P2P, err error) {
	round5Outputs = make([]map[helper_types.IdentityHash]*lindell17_dkg.Round5P2P, len(participants))
	for i := range participants {
		round5Outputs[i], err = participants[i].Round5(round5Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round5Outputs, nil
}

func MapDkgRound5OutputsToRound6Inputs(participants []*lindell17_dkg.Participant, round5UnicastOutputs []map[helper_types.IdentityHash]*lindell17_dkg.Round5P2P) (round6UnicastInputs []map[helper_types.IdentityHash]*lindell17_dkg.Round5P2P) {
	round6UnicastInputs = make([]map[helper_types.IdentityHash]*lindell17_dkg.Round5P2P, len(participants))
	for i := range participants {
		round6UnicastInputs[i] = make(map[helper_types.IdentityHash]*lindell17_dkg.Round5P2P)
		for j := range participants {
			if j != i {
				round6UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round5UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}

	return round6UnicastInputs
}

func DoDkgRound6(participants []*lindell17_dkg.Participant, round6Inputs []map[helper_types.IdentityHash]*lindell17_dkg.Round5P2P) (round6Outputs []map[helper_types.IdentityHash]*lindell17_dkg.Round6P2P, err error) {
	round6Outputs = make([]map[helper_types.IdentityHash]*lindell17_dkg.Round6P2P, len(participants))
	for i := range participants {
		round6Outputs[i], err = participants[i].Round6(round6Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round6Outputs, nil
}

func MapDkgRound6OutputsToRound7Inputs(participants []*lindell17_dkg.Participant, round6UnicastOutputs []map[helper_types.IdentityHash]*lindell17_dkg.Round6P2P) (round7UnicastInputs []map[helper_types.IdentityHash]*lindell17_dkg.Round6P2P) {
	round7UnicastInputs = make([]map[helper_types.IdentityHash]*lindell17_dkg.Round6P2P, len(participants))
	for i := range participants {
		round7UnicastInputs[i] = make(map[helper_types.IdentityHash]*lindell17_dkg.Round6P2P)
		for j := range participants {
			if j != i {
				round7UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round6UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}

	return round7UnicastInputs
}

func DoDkgRound7(participants []*lindell17_dkg.Participant, round7Inputs []map[helper_types.IdentityHash]*lindell17_dkg.Round6P2P) (round7Outputs []map[helper_types.IdentityHash]*lindell17_dkg.Round7P2P, err error) {
	round7Outputs = make([]map[helper_types.IdentityHash]*lindell17_dkg.Round7P2P, len(participants))
	for i := range participants {
		round7Outputs[i], err = participants[i].Round7(round7Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return round7Outputs, nil
}

func MapDkgRound7OutputsToRound8Inputs(participants []*lindell17_dkg.Participant, round7UnicastOutputs []map[helper_types.IdentityHash]*lindell17_dkg.Round7P2P) (round8UnicastInputs []map[helper_types.IdentityHash]*lindell17_dkg.Round7P2P) {
	round8UnicastInputs = make([]map[helper_types.IdentityHash]*lindell17_dkg.Round7P2P, len(participants))
	for i := range participants {
		round8UnicastInputs[i] = make(map[helper_types.IdentityHash]*lindell17_dkg.Round7P2P)
		for j := range participants {
			if j != i {
				round8UnicastInputs[i][participants[j].GetIdentityKey().Hash()] = round7UnicastOutputs[j][participants[i].GetIdentityKey().Hash()]
			}
		}
	}

	return round8UnicastInputs
}

func DoDkgRound8(participants []*lindell17_dkg.Participant, round8Inputs []map[helper_types.IdentityHash]*lindell17_dkg.Round7P2P) (shards []*lindell17.Shard, err error) {
	shards = make([]*lindell17.Shard, len(participants))
	for i := range participants {
		shards[i], err = participants[i].Round8(round8Inputs[i])
		if err != nil {
			return nil, err
		}
	}
	return shards, nil
}

func DoKeygen(cipherSuite *integration.CipherSuite, identities []integration.IdentityKey, transcripts []transcripts.Transcript, t int) ([]*threshold.SigningKeyShare, []*lindell17_dkg.Participant, []*lindell17.Shard, error) {

	cohortConfig, err := test_utils.MakeCohortProtocol(cipherSuite, protocols.FROST, identities, t, identities)
	if err != nil {
		return nil, nil, nil, err
	}
	uniqueSessionId, err := agreeonrandom_test_utils.ProduceSharedRandomValue(cipherSuite.Curve, identities, crand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	gennaroParticipants, err := gennaro_dkg_test_utils.MakeParticipants(uniqueSessionId, cohortConfig, identities, nil)
	if err != nil {
		return nil, nil, nil, err
	}

	r1OutsB, r1OutsU, err := gennaro_dkg_test_utils.DoDkgRound1(gennaroParticipants)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, out := range r1OutsU {
		if len(out) != cohortConfig.Protocol.TotalParties-1 {
			return nil, nil, nil, errs.NewFailed("output size does not match")
		}
	}

	r2InsB, r2InsU := gennaro_dkg_test_utils.MapDkgRound1OutputsToRound2Inputs(gennaroParticipants, r1OutsB, r1OutsU)
	r2Outs, err := gennaro_dkg_test_utils.DoDkgRound2(gennaroParticipants, r2InsB, r2InsU)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, out := range r2Outs {
		if out == nil {
			return nil, nil, nil, errs.NewFailed("output is nil")
		}
	}
	r3Ins := gennaro_dkg_test_utils.MapDkgRound2OutputsToRound3Inputs(gennaroParticipants, r2Outs)
	signingKeyShares, publicKeyShares, err := gennaro_dkg_test_utils.DoDkgRound3(gennaroParticipants, r3Ins)
	if err != nil {
		return nil, nil, nil, err
	}

	lindellParticipants, err := MakeParticipants([]byte("sid"), cohortConfig, identities, signingKeyShares, publicKeyShares, transcripts, nil)
	if err != nil {
		return nil, nil, nil, err
	}

	r1o, err := DoDkgRound1(lindellParticipants)
	if err != nil {
		return nil, nil, nil, err
	}

	r2i := MapDkgRound1OutputsToRound2Inputs(lindellParticipants, r1o)
	r2o, err := DoDkgRound2(lindellParticipants, r2i)
	if err != nil {
		return nil, nil, nil, err
	}

	r3i := MapDkgRound2OutputsToRound3Inputs(lindellParticipants, r2o)
	r3o, err := DoDkgRound3(lindellParticipants, r3i)
	if err != nil {
		return nil, nil, nil, err
	}

	r4i := MapDkgRound3OutputsToRound4Inputs(lindellParticipants, r3o)
	r4o, err := DoDkgRound4(lindellParticipants, r4i)
	if err != nil {
		return nil, nil, nil, err
	}

	r5i := MapDkgRound4OutputsToRound5Inputs(lindellParticipants, r4o)
	r5o, err := DoDkgRound5(lindellParticipants, r5i)
	if err != nil {
		return nil, nil, nil, err
	}

	r6i := MapDkgRound5OutputsToRound6Inputs(lindellParticipants, r5o)
	r6o, err := DoDkgRound6(lindellParticipants, r6i)
	if err != nil {
		return nil, nil, nil, err
	}

	r7i := MapDkgRound6OutputsToRound7Inputs(lindellParticipants, r6o)
	r7o, err := DoDkgRound7(lindellParticipants, r7i)
	if err != nil {
		return nil, nil, nil, err
	}

	r8i := MapDkgRound7OutputsToRound8Inputs(lindellParticipants, r7o)
	shards, err := DoDkgRound8(lindellParticipants, r8i)
	if err != nil {
		return nil, nil, nil, err
	}
	if shards == nil {
		return nil, nil, nil, errs.NewFailed("shards are nil")
	}
	return signingKeyShares, lindellParticipants, shards, nil
}
