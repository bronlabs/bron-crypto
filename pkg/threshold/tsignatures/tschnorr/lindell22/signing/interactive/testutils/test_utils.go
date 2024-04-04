package testutils

import (
	crand "crypto/rand"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	interactive_signing "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/signing/interactive"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

var cn = randomisedFischlin.Name

func MakeParticipants[V schnorr.Variant[V]](sid []byte, protocol types.ThresholdSignatureProtocol, identities []types.IdentityKey, shards ds.Map[types.IdentityKey, *lindell22.Shard], allTranscripts []transcripts.Transcript, variant schnorr.Variant[V]) (participants []*interactive_signing.Cosigner[V], err error) {
	if len(identities) < int(protocol.Threshold()) {
		return nil, errs.NewLength("invalid number of identities %d != %d", len(identities), protocol.Threshold())
	}

	prng := crand.Reader
	participants = make([]*interactive_signing.Cosigner[V], protocol.Threshold())
	for i, identity := range identities {
		if !protocol.Participants().Contains(identity) {
			return nil, errs.NewMissing("protocol config is missing identity")
		}
		thisShard, exists := shards.Get(identity)
		if !exists {
			return nil, errs.NewMissing("shard for idnetity %x", identity)
		}
		participants[i], err = interactive_signing.NewCosigner[V](identity.(types.AuthKey), sid, hashset.NewHashableHashSet(identities...), thisShard, protocol, cn, allTranscripts[i], variant, prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to create cosigner")
		}
	}

	return participants, nil
}

func DoRound1[V schnorr.Variant[V]](participants []*interactive_signing.Cosigner[V]) (round2BroadcastInputs []network.RoundMessages[types.ThresholdSignatureProtocol, *interactive_signing.Round1Broadcast], err error) {
	round1BroadcastOutputs := make([]*interactive_signing.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1BroadcastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to do lindell22 round 1")
		}
	}

	return testutils.MapBroadcastO2I(participants, round1BroadcastOutputs), nil
}

func DoRound2[V schnorr.Variant[V]](participants []*interactive_signing.Cosigner[V], round2BroadcastInputs []network.RoundMessages[types.ThresholdSignatureProtocol, *interactive_signing.Round1Broadcast]) (round3BroadcastInputs []network.RoundMessages[types.ThresholdSignatureProtocol, *interactive_signing.Round2Broadcast], err error) {
	round2BroadcastOutputs := make([]*interactive_signing.Round2Broadcast, len(participants))
	for i, participant := range participants {
		round2BroadcastOutputs[i], err = participant.Round2(round2BroadcastInputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to do lindell22 round 2")
		}
	}

	return testutils.MapBroadcastO2I(participants, round2BroadcastOutputs), nil
}

func DoRound3[V schnorr.Variant[V]](participants []*interactive_signing.Cosigner[V], round3BroadcastInputs []network.RoundMessages[types.ThresholdSignatureProtocol, *interactive_signing.Round2Broadcast], message []byte) (partialSignatures []*tschnorr.PartialSignature, err error) {
	partialSignatures = make([]*tschnorr.PartialSignature, len(participants))
	for i, participant := range participants {
		partialSignatures[i], err = participant.Round3(round3BroadcastInputs[i], message)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to do lindell22 round 3")
		}
	}

	return partialSignatures, nil
}

func RunInteractiveSigning[V schnorr.Variant[V]](participants []*interactive_signing.Cosigner[V], message []byte) (partialSignatures []*tschnorr.PartialSignature, err error) {
	r2bi, err := DoRound1(participants)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to do lindell22 round 1")
	}

	r3bi, err := DoRound2(participants, r2bi)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to do lindell22 round 2")
	}

	partialSignatures, err = DoRound3(participants, r3bi, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to do lindell22 round 3")
	}
	return partialSignatures, nil
}
