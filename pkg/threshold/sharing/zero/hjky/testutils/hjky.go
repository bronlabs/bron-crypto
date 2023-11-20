package testutils

import (
	crand "crypto/rand"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/hjky"
)

func MakeParticipants(uniqueSessionId []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, prngs []io.Reader) (participants []*hjky.Participant, err error) {
	if len(identities) != cohortConfig.Protocol.TotalParties {
		return nil, errs.NewInvalidLength("invalid number of identities %d != %d", len(identities), cohortConfig.Protocol.TotalParties)
	}

	participants = make([]*hjky.Participant, cohortConfig.Protocol.TotalParties)
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

		participants[i], err = hjky.NewParticipant(uniqueSessionId, identity.(integration.AuthKey), cohortConfig, nil, prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
	}

	return participants, nil
}

func DoDkgRound1(participants []*hjky.Participant) (round1BroadcastOutputs []*hjky.Round1Broadcast, round1UnicastOutputs []map[types.IdentityHash]*hjky.Round1P2P, err error) {
	round1BroadcastOutputs = make([]*hjky.Round1Broadcast, len(participants))
	round1UnicastOutputs = make([]map[types.IdentityHash]*hjky.Round1P2P, len(participants))
	for i, participant := range participants {
		round1BroadcastOutputs[i], round1UnicastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not run HJKY DKG round 1")
		}
	}

	return round1BroadcastOutputs, round1UnicastOutputs, nil
}

func DoDkgRound2(participants []*hjky.Participant, round2BroadcastInputs []map[types.IdentityHash]*hjky.Round1Broadcast, round2UnicastInputs []map[types.IdentityHash]*hjky.Round1P2P) (samples []hjky.Sample, publicKeySharesMaps []map[types.IdentityHash]curves.Point, feldmanCommitmentVectors [][]curves.Point, err error) {
	samples = make([]hjky.Sample, len(participants))
	publicKeySharesMaps = make([]map[types.IdentityHash]curves.Point, len(participants))
	feldmanCommitmentVectors = make([][]curves.Point, len(participants))
	for i := range participants {
		samples[i], publicKeySharesMaps[i], feldmanCommitmentVectors[i], err = participants[i].Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
		if err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "could not run HJKY DKG round 2")
		}
	}

	return samples, publicKeySharesMaps, feldmanCommitmentVectors, nil
}

func RunSample(sid []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey) (participants []*hjky.Participant, samples []hjky.Sample, publicKeySharesMaps []map[types.IdentityHash]curves.Point, feldmanCommitmentVectors [][]curves.Point, err error) {
	participants, err = MakeParticipants(sid, cohortConfig, identities, nil)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	r1OutsB, r1OutsU, err := DoDkgRound1(participants)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	r2InsB, r2InsU := integration_testutils.MapO2I(participants, r1OutsB, r1OutsU)
	samples, publicKeySharesMaps, feldmanCommitmentVectors, err = DoDkgRound2(participants, r2InsB, r2InsU)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return participants, samples, publicKeySharesMaps, feldmanCommitmentVectors, nil
}
