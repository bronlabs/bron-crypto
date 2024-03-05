package testutils

import (
	crand "crypto/rand"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	interactive_signing "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/signing/interactive"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

var cn = randomisedFischlin.Name

func MakeParticipants[F schnorr.Variant[F]](sid []byte, protocol types.ThresholdSignatureProtocol, identities []types.IdentityKey, shards ds.Map[types.IdentityKey, *lindell22.Shard], allTranscripts []transcripts.Transcript, variant schnorr.Variant[F]) (participants []*interactive_signing.Cosigner[F], err error) {
	if len(identities) < int(protocol.Threshold()) {
		return nil, errs.NewLength("invalid number of identities %d != %d", len(identities), protocol.Threshold())
	}

	prng := crand.Reader
	participants = make([]*interactive_signing.Cosigner[F], protocol.Threshold())
	for i, identity := range identities {
		if !protocol.Participants().Contains(identity) {
			return nil, errs.NewMissing("protocol config is missing identity")
		}
		thisShard, exists := shards.Get(identity)
		if !exists {
			return nil, errs.NewMissing("shard for idnetity %x", identity)
		}
		participants[i], err = interactive_signing.NewCosigner(identity.(types.AuthKey), sid, hashset.NewHashableHashSet(identities...), thisShard, protocol, cn, allTranscripts[i], variant, prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to create cosigner")
		}
	}

	return participants, nil
}

func DoRound1[F schnorr.Variant[F]](participants []*interactive_signing.Cosigner[F]) (round2BroadcastInputs []types.RoundMessages[*interactive_signing.Round1Broadcast], round2UnicastInputs []types.RoundMessages[*interactive_signing.Round1P2P], err error) {
	round1BroadcastOutputs := make([]*interactive_signing.Round1Broadcast, len(participants))
	round1UnicastOutputs := make([]types.RoundMessages[*interactive_signing.Round1P2P], len(participants))
	for i, participant := range participants {
		round1BroadcastOutputs[i], round1UnicastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "failed to do lindell22 round 1")
		}
	}

	round2BroadcastInputs = make([]types.RoundMessages[*interactive_signing.Round1Broadcast], len(participants))
	round2UnicastInputs = make([]types.RoundMessages[*interactive_signing.Round1P2P], len(participants))
	for i := range participants {
		round2BroadcastInputs[i] = types.NewRoundMessages[*interactive_signing.Round1Broadcast]()
		round2UnicastInputs[i] = types.NewRoundMessages[*interactive_signing.Round1P2P]()
		for j := range participants {
			if i == j {
				continue
			}
			round2BroadcastInputs[i].Put(participants[j].IdentityKey(), round1BroadcastOutputs[j])
			uio, exists := round1UnicastOutputs[j].Get(participants[i].IdentityKey())
			if !exists {
				return nil, nil, errs.NewMissing("%d", i)
			}
			round2UnicastInputs[i].Put(participants[j].IdentityKey(), uio)
		}
	}

	return round2BroadcastInputs, round2UnicastInputs, nil
}

func DoRound2[F schnorr.Variant[F]](participants []*interactive_signing.Cosigner[F], round2BroadcastInputs []types.RoundMessages[*interactive_signing.Round1Broadcast], round2UnicastInputs []types.RoundMessages[*interactive_signing.Round1P2P]) (round3BroadcastInputs []types.RoundMessages[*interactive_signing.Round2Broadcast], round3UnicastInputs []types.RoundMessages[*interactive_signing.Round2P2P], err error) {
	round2BroadcastOutputs := make([]*interactive_signing.Round2Broadcast, len(participants))
	round2UnicastOutputs := make([]types.RoundMessages[*interactive_signing.Round2P2P], len(participants))
	for i, participant := range participants {
		round2BroadcastOutputs[i], round2UnicastOutputs[i], err = participant.Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "failed to do lindell22 round 2")
		}
	}

	round3BroadcastInputs = make([]types.RoundMessages[*interactive_signing.Round2Broadcast], len(participants))
	round3UnicastInputs = make([]types.RoundMessages[*interactive_signing.Round2P2P], len(participants))
	for i := range participants {
		round3BroadcastInputs[i] = types.NewRoundMessages[*interactive_signing.Round2Broadcast]()
		round3UnicastInputs[i] = types.NewRoundMessages[*interactive_signing.Round2P2P]()
		for j := range participants {
			if i == j {
				continue
			}

			round3BroadcastInputs[i].Put(participants[j].IdentityKey(), round2BroadcastOutputs[j])
			uio, exists := round2UnicastOutputs[j].Get(participants[i].IdentityKey())
			if !exists {
				return nil, nil, errs.NewMissing("%d", i)
			}
			round3UnicastInputs[i].Put(participants[j].IdentityKey(), uio)
		}
	}

	return round3BroadcastInputs, round3UnicastInputs, nil
}

func DoRound3[F schnorr.Variant[F]](participants []*interactive_signing.Cosigner[F], round3BroadcastInputs []types.RoundMessages[*interactive_signing.Round2Broadcast], round3UnicastInputs []types.RoundMessages[*interactive_signing.Round2P2P], message []byte) (partialSignatures []*lindell22.PartialSignature, err error) {
	partialSignatures = make([]*lindell22.PartialSignature, len(participants))
	for i, participant := range participants {
		partialSignatures[i], err = participant.Round3(round3BroadcastInputs[i], round3UnicastInputs[i], message)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to do lindell22 round 3")
		}
	}

	return partialSignatures, nil
}

func RunInteractiveSigning[F schnorr.Variant[F]](participants []*interactive_signing.Cosigner[F], message []byte) (partialSignatures []*lindell22.PartialSignature, err error) {
	r2bi, r2ui, err := DoRound1(participants)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to do lindell22 round 1")
	}

	r3bi, r3ui, err := DoRound2(participants, r2bi, r2ui)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to do lindell22 round 2")
	}

	partialSignatures, err = DoRound3(participants, r3bi, r3ui, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to do lindell22 round 3")
	}
	return partialSignatures, nil
}
