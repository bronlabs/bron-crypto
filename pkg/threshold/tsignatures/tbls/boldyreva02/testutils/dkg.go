package testutils

import (
	crand "crypto/rand"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/keygen/dkg"
)

func MakeDkgParticipants[K bls.KeySubGroup](uniqueSessionId []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, prngs []io.Reader) (participants []*dkg.Participant[K], err error) {
	if len(identities) != cohortConfig.Participants.Len() {
		return nil, errs.NewInvalidLength("invalid number of identities %d != %d", len(identities), cohortConfig.Participants.Len())
	}

	participants = make([]*dkg.Participant[K], cohortConfig.Participants.Len())
	for i, identity := range identities {
		var prng io.Reader
		if len(prngs) != 0 && prngs[i] != nil {
			prng = prngs[i]
		} else {
			prng = crand.Reader
		}

		if !cohortConfig.IsInCohort(identity) {
			return nil, errs.NewMissing("given test identity not in cohort (problem in tests?)")
		}
		participants[i], err = dkg.NewParticipant[K](uniqueSessionId, identity, cohortConfig, nil, prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
	}

	return participants, nil
}

func DoDkgRound1[K bls.KeySubGroup](participants []*dkg.Participant[K]) (round1BroadcastOutputs []*dkg.Round1Broadcast, round1UnicastOutputs []map[types.IdentityHash]*dkg.Round1P2P, err error) {
	round1BroadcastOutputs = make([]*dkg.Round1Broadcast, len(participants))
	round1UnicastOutputs = make([]map[types.IdentityHash]*dkg.Round1P2P, len(participants))
	for i, participant := range participants {
		round1BroadcastOutputs[i], round1UnicastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not run DKG round 1")
		}
	}

	return round1BroadcastOutputs, round1UnicastOutputs, nil
}

func DoDkgRound2[K bls.KeySubGroup](participants []*dkg.Participant[K], round2BroadcastInputs []map[types.IdentityHash]*dkg.Round1Broadcast, round2UnicastInputs []map[types.IdentityHash]*dkg.Round1P2P) (round2Outputs []*dkg.Round2Broadcast, err error) {
	round2Outputs = make([]*dkg.Round2Broadcast, len(participants))
	for i := range participants {
		round2Outputs[i], err = participants[i].Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run DKG round 2")
		}
	}
	return round2Outputs, nil
}

func DoDkgRound3[K bls.KeySubGroup](participants []*dkg.Participant[K], round3Inputs []map[types.IdentityHash]*dkg.Round2Broadcast) (shards []*boldyreva02.Shard[K], err error) {
	shards = make([]*boldyreva02.Shard[K], len(participants))
	for i := range participants {
		shards[i], err = participants[i].Round3(round3Inputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run DKG round 3")
		}
	}

	return shards, nil
}
