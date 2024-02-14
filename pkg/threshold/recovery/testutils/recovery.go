package testutils

import (
	crand "crypto/rand"
	"io"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randomised_fischlin"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/recovery"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
)

var cn = randomisedFischlin.Name

func MakeParticipants(uniqueSessionId []byte, protocol types.ThresholdProtocol, presentRecoverers []ds.HashSet[types.IdentityKey], identities []types.IdentityKey, lostPartyIndex int, signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PartialPublicKeys, prngs []io.Reader) (participants []*recovery.Participant, err error) {
	if len(identities) != int(protocol.TotalParties()) {
		return nil, errs.NewLength("invalid number of identities %d != %d", len(identities), protocol.TotalParties())
	}

	participants = make([]*recovery.Participant, protocol.TotalParties())
	for i, identity := range identities {
		var prng io.Reader
		if len(prngs) != 0 && prngs[i] != nil {
			prng = prngs[i]
		} else {
			prng = crand.Reader
		}

		if !protocol.Participants().Contains(identity) {
			return nil, errs.NewMissing("given test identity not in cohort (problem in tests?)")
		}

		if lostPartyIndex == i {
			participants[i], err = recovery.NewLostParty(uniqueSessionId, identity.(types.AuthKey), protocol, cn, presentRecoverers[i], publicKeyShares[i], nil, prng)
		} else {
			participants[i], err = recovery.NewRecoverer(uniqueSessionId, identity.(types.AuthKey), identities[lostPartyIndex], signingKeyShares[i], publicKeyShares[i], protocol, presentRecoverers[i], cn, nil, prng)
		}
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
	}

	return participants, nil
}

func DoRecoveryRound1(participants []*recovery.Participant) (round1BroadcastOutputs []*recovery.Round1Broadcast, round1UnicastOutputs []types.RoundMessages[*recovery.Round1P2P], err error) {
	round1BroadcastOutputs = make([]*recovery.Round1Broadcast, len(participants))
	round1UnicastOutputs = make([]types.RoundMessages[*recovery.Round1P2P], len(participants))
	for i, participant := range participants {
		round1BroadcastOutputs[i], round1UnicastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not run Recovery round 1")
		}
	}

	return round1BroadcastOutputs, round1UnicastOutputs, nil
}

func DoRecoveryRound2(participants []*recovery.Participant, lostPartyIndex int, round2BroadcastInputs []types.RoundMessages[*recovery.Round1Broadcast], round2UnicastInputs []types.RoundMessages[*recovery.Round1P2P]) (round2p2p []types.RoundMessages[*recovery.Round2P2P], err error) {
	round2p2p = make([]types.RoundMessages[*recovery.Round2P2P], len(participants))
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

func DoRecoveryRound3(participants []*recovery.Participant, lostPartyIndex int, round3UnicastInputs types.RoundMessages[*recovery.Round2P2P]) (signingKeyShare *tsignatures.SigningKeyShare, err error) {
	signingKeyShare, err = participants[lostPartyIndex].Round3(round3UnicastInputs)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not run Recovery round 3")
	}
	return signingKeyShare, nil
}

func RunRecovery(uniqueSessionId []byte, protocol types.ThresholdProtocol, presentRecoverers []ds.HashSet[types.IdentityKey], identities []types.IdentityKey, lostPartyIndex int, signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PartialPublicKeys, prngs []io.Reader) (participants []*recovery.Participant, recoveredShare *tsignatures.SigningKeyShare, err error) {
	participants, err = MakeParticipants(uniqueSessionId, protocol, presentRecoverers, identities, lostPartyIndex, signingKeyShares, publicKeyShares, prngs)
	if err != nil {
		return nil, nil, err
	}

	r1OutsB, r1OutsU, err := DoRecoveryRound1(participants)
	if err != nil {
		return nil, nil, err
	}

	r2InsB, r2InsU := ttu.MapO2I(participants, r1OutsB, r1OutsU)
	r2OutsU, err := DoRecoveryRound2(participants, lostPartyIndex, r2InsB, r2InsU)
	if err != nil {
		return nil, nil, err
	}

	r3InsU := ttu.MapUnicastO2I(participants, r2OutsU)
	recoveredShare, err = DoRecoveryRound3(participants, lostPartyIndex, r3InsU[lostPartyIndex])
	if err != nil {
		return nil, nil, err
	}
	return participants, recoveredShare, nil
}
