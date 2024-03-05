package testutils

import (
	crand "crypto/rand"

	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	noninteractive_signing "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/signing/noninteractive"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

var cn = randomisedFischlin.Name

func MakeTranscripts(label string, identities []types.IdentityKey) []transcripts.Transcript {
	allTranscripts := make([]transcripts.Transcript, len(identities))
	for i := range identities {
		allTranscripts[i] = hagrid.NewTranscript(label, nil)
	}

	return allTranscripts
}

func MakePreGenParticipants(identities []types.IdentityKey, sid []byte, protocol types.ThresholdProtocol, allTranscripts []transcripts.Transcript) (participants []*noninteractive_signing.PreGenParticipant, err error) {
	prng := crand.Reader
	parties := make([]*noninteractive_signing.PreGenParticipant, len(identities))
	for i := range identities {
		parties[i], err = noninteractive_signing.NewPreGenParticipant(sid, allTranscripts[i], identities[i].(types.AuthKey), protocol, hashset.NewHashableHashSet(identities...), cn, prng)
		if err != nil {
			return nil, err
		}
	}

	return parties, nil
}

func DoPreGenRound1(participants []*noninteractive_signing.PreGenParticipant) (output []types.RoundMessages[*noninteractive_signing.Round1Broadcast], err error) {
	result := make([]types.RoundMessages[*noninteractive_signing.Round1Broadcast], len(participants))
	for i := range participants {
		result[i] = types.NewRoundMessages[*noninteractive_signing.Round1Broadcast]()
	}

	for i, party := range participants {
		out, err := participants[i].Round1()
		if err != nil {
			return nil, err
		}
		for j := range participants {
			if j != i {
				result[j].Put(party.IdentityKey(), out)
			}
		}
	}

	return result, nil
}

func DoPreGenRound2(participants []*noninteractive_signing.PreGenParticipant, input []types.RoundMessages[*noninteractive_signing.Round1Broadcast]) (output []types.RoundMessages[*noninteractive_signing.Round2Broadcast], err error) {
	result := make([]types.RoundMessages[*noninteractive_signing.Round2Broadcast], len(participants))
	for i := range participants {
		result[i] = types.NewRoundMessages[*noninteractive_signing.Round2Broadcast]()
	}

	for i, party := range participants {
		out, err := participants[i].Round2(input[i])
		if err != nil {
			return nil, err
		}
		for j := range participants {
			if j != i {
				result[j].Put(party.IdentityKey(), out)
			}
		}
	}

	return result, nil
}

func DoPreGenRound3(participants []*noninteractive_signing.PreGenParticipant, input []types.RoundMessages[*noninteractive_signing.Round2Broadcast]) (output []*lindell17.PreProcessingMaterial, err error) {
	result := make([]*lindell17.PreProcessingMaterial, len(participants))

	for i := range participants {
		out, err := participants[i].Round3(input[i])
		if err != nil {
			return nil, err
		}
		result[i] = out
	}

	return result, nil
}

func DoLindell2017PreGen(participants []*noninteractive_signing.PreGenParticipant) (output []*lindell17.PreProcessingMaterial, err error) {
	r1, err := DoPreGenRound1(participants)
	if err != nil {
		return nil, err
	}
	r2, err := DoPreGenRound2(participants, r1)
	if err != nil {
		return nil, err
	}
	return DoPreGenRound3(participants, r2)
}
