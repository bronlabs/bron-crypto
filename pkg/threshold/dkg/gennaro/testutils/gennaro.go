package testutils

import (
	crand "crypto/rand"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/gennaro"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
)

func MakeParticipants(uniqueSessionId []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, prngs []io.Reader) (participants []*gennaro.Participant, err error) {
	if len(identities) != cohortConfig.Protocol.TotalParties {
		return nil, errs.NewInvalidLength("invalid number of identities %d != %d", len(identities), cohortConfig.Protocol.TotalParties)
	}

	participants = make([]*gennaro.Participant, cohortConfig.Protocol.TotalParties)
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
		participants[i], err = gennaro.NewParticipant(uniqueSessionId, identity.(integration.AuthKey), cohortConfig, prng, nil)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
	}

	return participants, nil
}

func DoDkgRound1(participants []*gennaro.Participant) (round1BroadcastOutputs []*gennaro.Round1Broadcast, round1UnicastOutputs []map[types.IdentityHash]*gennaro.Round1P2P, err error) {
	round1BroadcastOutputs = make([]*gennaro.Round1Broadcast, len(participants))
	round1UnicastOutputs = make([]map[types.IdentityHash]*gennaro.Round1P2P, len(participants))
	for i, participant := range participants {
		round1BroadcastOutputs[i], round1UnicastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not run Gennaro DKG round 1")
		}
	}

	return round1BroadcastOutputs, round1UnicastOutputs, nil
}

func DoDkgRound2(participants []*gennaro.Participant, round2BroadcastInputs []map[types.IdentityHash]*gennaro.Round1Broadcast, round2UnicastInputs []map[types.IdentityHash]*gennaro.Round1P2P) (round2Outputs []*gennaro.Round2Broadcast, err error) {
	round2Outputs = make([]*gennaro.Round2Broadcast, len(participants))
	for i := range participants {
		round2Outputs[i], err = participants[i].Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run Gennaro DKG round 2")
		}
	}
	return round2Outputs, nil
}

func DoDkgRound3(participants []*gennaro.Participant, round3Inputs []map[types.IdentityHash]*gennaro.Round2Broadcast) (signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PublicKeyShares, err error) {
	signingKeyShares = make([]*tsignatures.SigningKeyShare, len(participants))
	publicKeyShares = make([]*tsignatures.PublicKeyShares, len(participants))
	for i := range participants {
		signingKeyShares[i], publicKeyShares[i], err = participants[i].Round3(round3Inputs[i])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not run Gennaro DKG round 3")
		}
	}

	return signingKeyShares, publicKeyShares, nil
}

func RunDKG(uniqueSessionId []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey) (signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PublicKeyShares, err error) {
	participants, err := MakeParticipants(uniqueSessionId, cohortConfig, identities, nil)
	if err != nil {
		return nil, nil, err
	}

	r1OutsB, r1OutsU, err := DoDkgRound1(participants)
	if err != nil {
		return nil, nil, err
	}

	r2InsB, r2InsU := integration_testutils.MapO2I(participants, r1OutsB, r1OutsU)
	r2OutsB, err := DoDkgRound2(participants, r2InsB, r2InsU)
	if err != nil {
		return nil, nil, err
	}

	r3InsB := integration_testutils.MapBroadcastO2I(participants, r2OutsB)
	signingKeyShares, publicKeyShares, err = DoDkgRound3(participants, r3InsB)
	if err != nil {
		return nil, nil, err
	}
	return signingKeyShares, publicKeyShares, nil
}
