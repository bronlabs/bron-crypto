package testutils

import (
	crand "crypto/rand"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/recovery"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
)

func MakeParticipants(uniqueSessionId []byte, cohortConfig *integration.CohortConfig, presentRecoverers []*hashset.HashSet[integration.IdentityKey], identities []integration.IdentityKey, lostPartyIndex int, signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PublicKeyShares, prngs []io.Reader) (participants []*recovery.Participant, err error) {
	if len(identities) != cohortConfig.Protocol.TotalParties {
		return nil, errs.NewInvalidLength("invalid number of identities %d != %d", len(identities), cohortConfig.Protocol.TotalParties)
	}

	participants = make([]*recovery.Participant, cohortConfig.Protocol.TotalParties)
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

		if lostPartyIndex == i {
			participants[i], err = recovery.NewLostParty(uniqueSessionId, identity.(integration.AuthKey), publicKeyShares[i], cohortConfig, presentRecoverers[i], nil, prng)
		} else {
			participants[i], err = recovery.NewRecoverer(uniqueSessionId, identity.(integration.AuthKey), identities[lostPartyIndex], signingKeyShares[i], publicKeyShares[i], cohortConfig, presentRecoverers[i], nil, prng)
		}
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
	}

	return participants, nil
}

func DoRecoveryRound1(participants []*recovery.Participant) (round1BroadcastOutputs []*recovery.Round1Broadcast, round1UnicastOutputs []map[types.IdentityHash]*recovery.Round1P2P, err error) {
	round1BroadcastOutputs = make([]*recovery.Round1Broadcast, len(participants))
	round1UnicastOutputs = make([]map[types.IdentityHash]*recovery.Round1P2P, len(participants))
	for i, participant := range participants {
		round1BroadcastOutputs[i], round1UnicastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not run Recovery round 1")
		}
	}

	return round1BroadcastOutputs, round1UnicastOutputs, nil
}

func DoRecoveryRound2(participants []*recovery.Participant, lostPartyIndex int, round2BroadcastInputs []map[types.IdentityHash]*recovery.Round1Broadcast, round2UnicastInputs []map[types.IdentityHash]*recovery.Round1P2P) (round2p2p []map[types.IdentityHash]*recovery.Round2P2P, err error) {
	round2p2p = make([]map[types.IdentityHash]*recovery.Round2P2P, len(participants))
	lastRecorded := 0
	for i, participant := range participants {
		round2p2p[lastRecorded], err = participant.Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run Recovery round 2")
		}
		lastRecorded++
	}
	return round2p2p, nil
}

func DoRecoveryRound3(participants []*recovery.Participant, lostPartyIndex int, round3UnicastInputs map[types.IdentityHash]*recovery.Round2P2P) (signingKeyShare *tsignatures.SigningKeyShare, err error) {
	signingKeyShare, err = participants[lostPartyIndex].Round3(round3UnicastInputs)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not run Recovery round 3")
	}
	return signingKeyShare, nil
}

func RunRecovery(uniqueSessionId []byte, cohortConfig *integration.CohortConfig, presentRecoverers []*hashset.HashSet[integration.IdentityKey], identities []integration.IdentityKey, lostPartyIndex int, signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PublicKeyShares, prngs []io.Reader) (participants []*recovery.Participant, recoveredShare *tsignatures.SigningKeyShare, err error) {
	participants, err = MakeParticipants(uniqueSessionId, cohortConfig, presentRecoverers, identities, lostPartyIndex, signingKeyShares, publicKeyShares, prngs)
	if err != nil {
		return nil, nil, err
	}

	r1OutsB, r1OutsU, err := DoRecoveryRound1(participants)
	if err != nil {
		return nil, nil, err
	}

	r2InsB, r2InsU := integration_testutils.MapO2I(participants, r1OutsB, r1OutsU)
	r2OutsU, err := DoRecoveryRound2(participants, lostPartyIndex, r2InsB, r2InsU)
	if err != nil {
		return nil, nil, err
	}

	r3InsU := integration_testutils.MapUnicastO2I(participants, r2OutsU)
	recoveredShare, err = DoRecoveryRound3(participants, lostPartyIndex, r3InsU[lostPartyIndex])
	if err != nil {
		return nil, nil, err
	}
	return participants, recoveredShare, nil
}
