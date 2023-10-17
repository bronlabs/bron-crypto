package testutils

import (
	crand "crypto/rand"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/refresh"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
)

func MakeParticipants(uniqueSessionId []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PublicKeyShares, prngs []io.Reader) (participants []*refresh.Participant, err error) {
	if len(identities) != cohortConfig.Protocol.TotalParties {
		return nil, errs.NewInvalidLength("invalid number of identities %d != %d", len(identities), cohortConfig.Protocol.TotalParties)
	}

	participants = make([]*refresh.Participant, cohortConfig.Protocol.TotalParties)
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

		participants[i], err = refresh.NewParticipant(uniqueSessionId, identity, signingKeyShares[i], publicKeyShares[i], cohortConfig, nil, prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
	}

	return participants, nil
}

func DoDkgRound1(participants []*refresh.Participant) (round1BroadcastOutputs []*refresh.Round1Broadcast, round1UnicastOutputs []map[types.IdentityHash]*refresh.Round1P2P, err error) {
	round1BroadcastOutputs = make([]*refresh.Round1Broadcast, len(participants))
	round1UnicastOutputs = make([]map[types.IdentityHash]*refresh.Round1P2P, len(participants))
	for i, participant := range participants {
		round1BroadcastOutputs[i], round1UnicastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not run Refresh DKG round 1")
		}
	}

	return round1BroadcastOutputs, round1UnicastOutputs, nil
}

func DoDkgRound2(participants []*refresh.Participant, round2BroadcastInputs []map[types.IdentityHash]*refresh.Round1Broadcast, round2UnicastInputs []map[types.IdentityHash]*refresh.Round1P2P) (signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PublicKeyShares, err error) {
	signingKeyShares = make([]*tsignatures.SigningKeyShare, len(participants))
	publicKeyShares = make([]*tsignatures.PublicKeyShares, len(participants))
	for i := range participants {
		signingKeyShares[i], publicKeyShares[i], err = participants[i].Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not run Refresh DKG round 2")
		}
	}

	return signingKeyShares, publicKeyShares, nil
}

func RunRefresh(sid []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, initialSigningKeyShares []*tsignatures.SigningKeyShare, initialPublicKeyShares []*tsignatures.PublicKeyShares) (participants []*refresh.Participant, signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PublicKeyShares, err error) {
	participants, err = MakeParticipants(sid, cohortConfig, identities, initialSigningKeyShares, initialPublicKeyShares, nil)
	if err != nil {
		return nil, nil, nil, err
	}

	r1OutsB, r1OutsU, err := DoDkgRound1(participants)
	if err != nil {
		return nil, nil, nil, err
	}

	r2InsB, r2InsU := integration_testutils.MapO2I(participants, r1OutsB, r1OutsU)
	signingKeyShares, publicKeyShares, err = DoDkgRound2(participants, r2InsB, r2InsU)
	if err != nil {
		return nil, nil, nil, err
	}
	return participants, signingKeyShares, publicKeyShares, nil
}
