package testutils

import (
	crand "crypto/rand"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randomised_fischlin"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	lindell17_dkg "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/dkg"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

var cn = randomisedFischlin.Name

func MakeParticipants(sid []byte, protocol types.ThresholdProtocol, identities []types.IdentityKey, signingShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PartialPublicKeys, allTranscripts []transcripts.Transcript, prngs []io.Reader) (participants []*lindell17_dkg.Participant, err error) {
	if len(identities) != int(protocol.TotalParties()) {
		return nil, errs.NewLength("invalid number of identities %d != %d", len(identities), protocol.TotalParties())
	}

	participants = make([]*lindell17_dkg.Participant, protocol.TotalParties())
	for i, identity := range identities {
		var prng io.Reader
		if len(prngs) != 0 && prngs[i] != nil {
			prng = prngs[i]
		} else {
			prng = crand.Reader
		}
		var transcript transcripts.Transcript
		if len(allTranscripts) != 0 && allTranscripts[i] != nil {
			transcript = allTranscripts[i]
		}

		if !protocol.Participants().Contains(identity) {
			return nil, errs.NewMissing("given test identity not in cohort (problem in tests?)")
		}
		participants[i], err = lindell17_dkg.NewParticipant(sid, identity.(types.AuthKey), signingShares[i], publicKeyShares[i], protocol, cn, prng, transcript)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
	}

	return participants, nil
}

func DoDkgRound1(participants []*lindell17_dkg.Participant) (round1BroadcastOutputs []*lindell17_dkg.Round1Broadcast, err error) {
	round1BroadcastOutputs = make([]*lindell17_dkg.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1BroadcastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run DKG round 1")
		}
	}

	return round1BroadcastOutputs, nil
}

func DoDkgRound2(participants []*lindell17_dkg.Participant, round2BroadcastInputs []types.RoundMessages[*lindell17_dkg.Round1Broadcast]) (round2Outputs []*lindell17_dkg.Round2Broadcast, err error) {
	round2Outputs = make([]*lindell17_dkg.Round2Broadcast, len(participants))
	for i := range participants {
		round2Outputs[i], err = participants[i].Round2(round2BroadcastInputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run DKG round 2")
		}
	}
	return round2Outputs, nil
}

func DoDkgRound3(participants []*lindell17_dkg.Participant, round3Inputs []types.RoundMessages[*lindell17_dkg.Round2Broadcast]) (round3Outputs []*lindell17_dkg.Round3Broadcast, err error) {
	round3Outputs = make([]*lindell17_dkg.Round3Broadcast, len(participants))
	for i := range participants {
		round3Outputs[i], err = participants[i].Round3(round3Inputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run DKG round 3")
		}
	}
	return round3Outputs, nil
}

func DoDkgRound4(participants []*lindell17_dkg.Participant, round4Inputs []types.RoundMessages[*lindell17_dkg.Round3Broadcast]) (round4Unicast []types.RoundMessages[*lindell17_dkg.Round4P2P], err error) {
	round4Outputs := make([]types.RoundMessages[*lindell17_dkg.Round4P2P], len(participants))
	for i := range participants {
		round4Outputs[i], err = participants[i].Round4(round4Inputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run DKG round 4")
		}
	}
	return round4Outputs, nil
}

func DoDkgRound5(participants []*lindell17_dkg.Participant, round5Inputs []types.RoundMessages[*lindell17_dkg.Round4P2P]) (round5Outputs []types.RoundMessages[*lindell17_dkg.Round5P2P], err error) {
	round5Outputs = make([]types.RoundMessages[*lindell17_dkg.Round5P2P], len(participants))
	for i := range participants {
		round5Outputs[i], err = participants[i].Round5(round5Inputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run DKG round 5")
		}
	}
	return round5Outputs, nil
}

func DoDkgRound6(participants []*lindell17_dkg.Participant, round6Inputs []types.RoundMessages[*lindell17_dkg.Round5P2P]) (round6Outputs []types.RoundMessages[*lindell17_dkg.Round6P2P], err error) {
	round6Outputs = make([]types.RoundMessages[*lindell17_dkg.Round6P2P], len(participants))
	for i := range participants {
		round6Outputs[i], err = participants[i].Round6(round6Inputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run DKG round 6")
		}
	}
	return round6Outputs, nil
}

func DoDkgRound7(participants []*lindell17_dkg.Participant, round7Inputs []types.RoundMessages[*lindell17_dkg.Round6P2P]) (round7Outputs []types.RoundMessages[*lindell17_dkg.Round7P2P], err error) {
	round7Outputs = make([]types.RoundMessages[*lindell17_dkg.Round7P2P], len(participants))
	for i := range participants {
		round7Outputs[i], err = participants[i].Round7(round7Inputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run DKG round 7")
		}
	}
	return round7Outputs, nil
}

func DoDkgRound8(participants []*lindell17_dkg.Participant, round8Inputs []types.RoundMessages[*lindell17_dkg.Round7P2P]) (shards []*lindell17.Shard, err error) {
	shards = make([]*lindell17.Shard, len(participants))
	for i := range participants {
		shards[i], err = participants[i].Round8(round8Inputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run DKG round 8")
		}
	}
	return shards, nil
}
