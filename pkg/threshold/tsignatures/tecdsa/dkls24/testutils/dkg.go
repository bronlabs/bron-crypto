package testutils

import (
	crand "crypto/rand"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/keygen/dkg"
)

func MakeDkgParticipants(curve curves.Curve, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, prngs []io.Reader, sid []byte) (participants []*dkg.Participant, err error) {
	if len(identities) != cohortConfig.Protocol.TotalParties {
		return nil, errs.NewInvalidLength("invalid number of identities %d != %d", len(identities), cohortConfig.Protocol.TotalParties)
	}

	participants = make([]*dkg.Participant, cohortConfig.Protocol.TotalParties)

	if len(sid) == 0 {
		sid, err = agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, crand.Reader)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct sid")
		}
	}

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

		participants[i], err = dkg.NewParticipant(sid, identity.(integration.AuthKey), cohortConfig, prng, nil)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
	}

	return participants, nil
}

func DoDkgRound1(participants []*dkg.Participant) (round1BroadcastOutputs []*dkg.Round1Broadcast, round1UnicastOutputs []map[types.IdentityHash]*dkg.Round1P2P, err error) {
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

func DoDkgRound2(participants []*dkg.Participant, round2BroadcastInputs []map[types.IdentityHash]*dkg.Round1Broadcast, round2UnicastInputs []map[types.IdentityHash]*dkg.Round1P2P) (round2BroadcastOutputs []*dkg.Round2Broadcast, round2UnicastOutputs []map[types.IdentityHash]*dkg.Round2P2P, err error) {
	round2BroadcastOutputs = make([]*dkg.Round2Broadcast, len(participants))
	round2UnicastOutputs = make([]map[types.IdentityHash]*dkg.Round2P2P, len(participants))
	for i := range participants {
		round2BroadcastOutputs[i], round2UnicastOutputs[i], err = participants[i].Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not run DKG round 2")
		}
	}
	return round2BroadcastOutputs, round2UnicastOutputs, nil
}

func DoDkgRound3(participants []*dkg.Participant, round3BroadcastInputs []map[types.IdentityHash]*dkg.Round2Broadcast, round3UnicastInputs []map[types.IdentityHash]*dkg.Round2P2P) (round3UnicastOutputs []map[types.IdentityHash]dkg.Round3P2P, err error) {
	round3UnicastOutputs = make([]map[types.IdentityHash]dkg.Round3P2P, len(participants))
	for i := range participants {
		round3UnicastOutputs[i], err = participants[i].Round3(round3BroadcastInputs[i], round3UnicastInputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run DKG round 3")
		}
	}

	return round3UnicastOutputs, nil
}

func DoDkgRound4(participants []*dkg.Participant, round4UnicastInputs []map[types.IdentityHash]dkg.Round3P2P) (round4UnicastOutputs []map[types.IdentityHash]dkg.Round4P2P, err error) {
	round4UnicastOutputs = make([]map[types.IdentityHash]dkg.Round4P2P, len(participants))
	for i := range participants {
		round4UnicastOutputs[i], err = participants[i].Round4(round4UnicastInputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run DKG round 4")
		}
	}

	return round4UnicastOutputs, nil
}

func DoDkgRound5(participants []*dkg.Participant, round5UnicastInputs []map[types.IdentityHash]dkg.Round4P2P) (round5UnicastOutputs []map[types.IdentityHash]dkg.Round5P2P, err error) {
	round5UnicastOutputs = make([]map[types.IdentityHash]dkg.Round5P2P, len(participants))
	for i := range participants {
		round5UnicastOutputs[i], err = participants[i].Round5(round5UnicastInputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run DKG round 5")
		}
	}

	return round5UnicastOutputs, nil
}

func DoDkgRound6(participants []*dkg.Participant, round6UnicastInputs []map[types.IdentityHash]dkg.Round5P2P) (shards []*dkls24.Shard, err error) {
	shards = make([]*dkls24.Shard, len(participants))
	for i := range participants {
		shards[i], err = participants[i].Round6(round6UnicastInputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run DKG round 6")
		}
	}

	return shards, nil
}

func RunDKG(curve curves.Curve, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey) (shards []*dkls24.Shard, err error) {
	participants, err := MakeDkgParticipants(curve, cohortConfig, identities, nil, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not make DKG participants")
	}

	r1OutsB, r1OutsU, err := DoDkgRound1(participants)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not run DKG round 1")
	}

	r2InsB, r2InsU := integration_testutils.MapO2I(participants, r1OutsB, r1OutsU)
	r2OutsB, r2OutsU, err := DoDkgRound2(participants, r2InsB, r2InsU)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not run DKG round 2")
	}

	r3InsB, r3InsU := integration_testutils.MapO2I(participants, r2OutsB, r2OutsU)
	r3OutsU, err := DoDkgRound3(participants, r3InsB, r3InsU)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not run DKG round 3")
	}

	r4InsU := integration_testutils.MapUnicastO2I(participants, r3OutsU)
	r4OutsU, err := DoDkgRound4(participants, r4InsU)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not run DKG round 4")
	}

	r5InsU := integration_testutils.MapUnicastO2I(participants, r4OutsU)
	r5OutsU, err := DoDkgRound5(participants, r5InsU)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not run DKG round 5")
	}

	r6InsU := integration_testutils.MapUnicastO2I(participants, r5OutsU)
	shards, err = DoDkgRound6(participants, r6InsU)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not run DKG round 6")
	}

	return shards, nil
}
