package testutils

import (
	crand "crypto/rand"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randomised_fischlin"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow/keygen/dkg"
)

var cn = randomisedFischlin.Name

func MakeDkgParticipants(uniqueSessionId []byte, protocol types.ThresholdProtocol, identities []types.IdentityKey, prngs []io.Reader) (participants []*dkg.Participant, err error) {
	if len(identities) != protocol.Participants().Size() {
		return nil, errs.NewLength("invalid number of identities %d != %d", len(identities), protocol.Participants().Size())
	}

	participants = make([]*dkg.Participant, protocol.Participants().Size())
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
		participants[i], err = dkg.NewParticipant(uniqueSessionId, identity.(types.AuthKey), protocol, cn, nil, prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
	}

	return participants, nil
}

func DoDkgRound1(participants []*dkg.Participant) (round1BroadcastOutputs []*dkg.Round1Broadcast, round1UnicastOutputs []types.RoundMessages[*dkg.Round1P2P], err error) {
	round1BroadcastOutputs = make([]*dkg.Round1Broadcast, len(participants))
	round1UnicastOutputs = make([]types.RoundMessages[*dkg.Round1P2P], len(participants))
	for i, participant := range participants {
		round1BroadcastOutputs[i], round1UnicastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not run glow DKG round 1")
		}
	}

	return round1BroadcastOutputs, round1UnicastOutputs, nil
}

func DoDkgRound2(participants []*dkg.Participant, round2BroadcastInputs []types.RoundMessages[*dkg.Round1Broadcast], round2UnicastInputs []types.RoundMessages[*dkg.Round1P2P]) (round2Outputs []*dkg.Round2Broadcast, err error) {
	round2Outputs = make([]*dkg.Round2Broadcast, len(participants))
	for i := range participants {
		round2Outputs[i], err = participants[i].Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run glow DKG round 2")
		}
	}
	return round2Outputs, nil
}

func DoDkgRound3(participants []*dkg.Participant, round3Inputs []types.RoundMessages[*dkg.Round2Broadcast]) (shards []*glow.Shard, err error) {
	shards = make([]*glow.Shard, len(participants))
	for i := range participants {
		shards[i], err = participants[i].Round3(round3Inputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run glow DKG round 3")
		}
	}

	return shards, nil
}
