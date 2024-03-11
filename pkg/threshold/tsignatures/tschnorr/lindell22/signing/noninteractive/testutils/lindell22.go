package testutils

import (
	crand "crypto/rand"

	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	noninteractive_signing "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/signing/noninteractive"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

var cn = randomisedFischlin.Name

func MakePreGenParticipants(identities []types.IdentityKey, sid []byte, protocol types.ThresholdProtocol, myTranscripts []transcripts.Transcript) (participants []*noninteractive_signing.PreGenParticipant, err error) {
	prng := crand.Reader
	parties := make([]*noninteractive_signing.PreGenParticipant, len(identities))
	for i := range identities {
		parties[i], err = noninteractive_signing.NewPreGenParticipant(identities[i].(types.AuthKey), sid, protocol, hashset.NewHashableHashSet(identities...), cn, myTranscripts[i], prng)
		if err != nil {
			return nil, err
		}
	}

	return parties, nil
}

func DoPreGenRound1(participants []*noninteractive_signing.PreGenParticipant) (round2BroadcastInputs []network.RoundMessages[*noninteractive_signing.Round1Broadcast], round2UnicastInputs []network.RoundMessages[*noninteractive_signing.Round1P2P], err error) {
	round1BroadcastOutputs := make([]*noninteractive_signing.Round1Broadcast, len(participants))
	round1UnicastOutputs := make([]network.RoundMessages[*noninteractive_signing.Round1P2P], len(participants))
	// round1
	for i, participant := range participants {
		round1BroadcastOutputs[i], round1UnicastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "failed to do lindell22 round 1")
		}
	}

	round2BroadcastInputs = make([]network.RoundMessages[*noninteractive_signing.Round1Broadcast], len(participants))
	round2UnicastInputs = make([]network.RoundMessages[*noninteractive_signing.Round1P2P], len(participants))
	for i := range participants {
		round2BroadcastInputs[i] = network.NewRoundMessages[*noninteractive_signing.Round1Broadcast]()
		round2UnicastInputs[i] = network.NewRoundMessages[*noninteractive_signing.Round1P2P]()
		for j := range participants {
			if i == j {
				continue
			}
			round2BroadcastInputs[i].Put(participants[j].IdentityKey(), round1BroadcastOutputs[j])
			msg, _ := round1UnicastOutputs[j].Get(participants[i].IdentityKey())
			round2UnicastInputs[i].Put(participants[j].IdentityKey(), msg)
		}
	}

	return round2BroadcastInputs, round2UnicastInputs, nil
}

func DoPreGenRound2(participants []*noninteractive_signing.PreGenParticipant, round2BroadcastInputs []network.RoundMessages[*noninteractive_signing.Round1Broadcast], round2UnicastInputs []network.RoundMessages[*noninteractive_signing.Round1P2P]) (round3BroadcastInputs []network.RoundMessages[*noninteractive_signing.Round2Broadcast], round3UnicastInputs []network.RoundMessages[*noninteractive_signing.Round2P2P], err error) {
	round2BroadcastOutputs := make([]*noninteractive_signing.Round2Broadcast, len(participants))
	round2UnicastOutputs := make([]network.RoundMessages[*noninteractive_signing.Round2P2P], len(participants))
	for i, participant := range participants {
		round2BroadcastOutputs[i], round2UnicastOutputs[i], err = participant.Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "failed to do lindell22 round 2")
		}
	}

	round3BroadcastInputs = make([]network.RoundMessages[*noninteractive_signing.Round2Broadcast], len(participants))
	round3UnicastInputs = make([]network.RoundMessages[*noninteractive_signing.Round2P2P], len(participants))
	for i := range participants {
		round3BroadcastInputs[i] = network.NewRoundMessages[*noninteractive_signing.Round2Broadcast]()
		round3UnicastInputs[i] = network.NewRoundMessages[*noninteractive_signing.Round2P2P]()
		for j := range participants {
			if i == j {
				continue
			}
			round3BroadcastInputs[i].Put(participants[j].IdentityKey(), round2BroadcastOutputs[j])
			msg, _ := round2UnicastOutputs[j].Get(participants[i].IdentityKey())
			round3UnicastInputs[i].Put(participants[j].IdentityKey(), msg)
		}
	}

	return round3BroadcastInputs, round3UnicastInputs, nil
}

func DoPreGenRound3(participants []*noninteractive_signing.PreGenParticipant, round3BroadcastInputs []network.RoundMessages[*noninteractive_signing.Round2Broadcast], round3UnicastInputs []network.RoundMessages[*noninteractive_signing.Round2P2P]) (output []*lindell22.PreProcessingMaterial, err error) {
	batches := make([]*lindell22.PreProcessingMaterial, len(participants))
	for i, participant := range participants {
		batches[i], err = participant.Round3(round3BroadcastInputs[i], round3UnicastInputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to do lindell22 round 3")
		}
	}

	return batches, nil
}

func DoLindell2022PreGen(participants []*noninteractive_signing.PreGenParticipant) (output []*lindell22.PreProcessingMaterial, err error) {
	r1b, r1u, err := DoPreGenRound1(participants)
	if err != nil {
		return nil, err
	}
	r2b, r2u, err := DoPreGenRound2(participants, r1b, r1u)
	if err != nil {
		return nil, err
	}
	return DoPreGenRound3(participants, r2b, r2u)
}
