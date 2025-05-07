package testutils

import (
	crand "crypto/rand"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	fiatShamir "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/stretchr/testify/require"
	"testing"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr/lindell22"
	interactive_signing "github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr/lindell22/signing/interactive"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const nizkCompilerName = fiatShamir.Name

func MakeParticipants[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S], V schnorr.Variant[V, M, P, F, S], M any](tb testing.TB, sid []byte, protocol types.ThresholdSignatureProtocol[C, P, F, S], identities []types.IdentityKey, shards ds.Map[types.IdentityKey, *lindell22.Shard[C, P, F, S]], allTranscripts []transcripts.Transcript, variant schnorr.Variant[V, M, P, F, S]) (participants []*interactive_signing.Cosigner[C, P, F, S, V, M]) {
	require.Len(tb, identities, int(protocol.Threshold()), "invalid number of identities %d != %d", len(identities), protocol.Threshold())

	var err error
	prng := crand.Reader
	participants = make([]*interactive_signing.Cosigner[C, P, F, S, V, M], protocol.Threshold())
	for i, identity := range identities {
		require.True(tb, protocol.Participants().Contains(identity), "protocol config is missing identity")
		thisShard, exists := shards.Get(identity)
		require.True(tb, exists, "shard for identity %x", identity)
		participants[i], err = interactive_signing.NewCosigner[C, P, F, S, V, M](identity.(types.AuthKey), sid, hashset.NewHashableHashSet(identities...), thisShard, protocol, nizkCompilerName, allTranscripts[i], variant, prng)
		require.NoError(tb, err, "failed to create cosigner")
	}

	return participants
}

func DoRound1[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S], V schnorr.Variant[V, M, P, F, S], M any](tb testing.TB, participants []*interactive_signing.Cosigner[C, P, F, S, V, M]) (round2BroadcastInputs []network.RoundMessages[*interactive_signing.Round1Broadcast]) {
	var err error
	round1BroadcastOutputs := make([]*interactive_signing.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1BroadcastOutputs[i], err = participant.Round1()
		require.NoError(tb, err, "failed to do lindell22 round 1")
	}

	return testutils.MapBroadcastO2I(tb, participants, round1BroadcastOutputs)
}

func DoRound2[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S], V schnorr.Variant[V, M, P, F, S], M any](tb testing.TB, participants []*interactive_signing.Cosigner[C, P, F, S, V, M], round2BroadcastInputs []network.RoundMessages[*interactive_signing.Round1Broadcast]) (round3BroadcastInputs []network.RoundMessages[*interactive_signing.Round2Broadcast[P, F, S]]) {
	var err error
	round2BroadcastOutputs := make([]*interactive_signing.Round2Broadcast[P, F, S], len(participants))
	for i, participant := range participants {
		round2BroadcastOutputs[i], err = participant.Round2(round2BroadcastInputs[i])
		require.NoError(tb, err, "failed to do lindell22 round 2")
	}

	return testutils.MapBroadcastO2I(tb, participants, round2BroadcastOutputs)
}

func DoRound3[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S], V schnorr.Variant[V, M, P, F, S], M any](tb testing.TB, participants []*interactive_signing.Cosigner[C, P, F, S, V, M], round3BroadcastInputs []network.RoundMessages[*interactive_signing.Round2Broadcast[P, F, S]], message M) (partialSignatures []*tschnorr.PartialSignature[P, F, S]) {
	var err error
	partialSignatures = make([]*tschnorr.PartialSignature[P, F, S], len(participants))
	for i, participant := range participants {
		partialSignatures[i], err = participant.Round3(round3BroadcastInputs[i], message)
		require.NoError(tb, err, "failed to do lindell22 round 3")
	}

	return partialSignatures
}

func RunInteractiveSigning[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S], V schnorr.Variant[V, M, P, F, S], M any](tb testing.TB, participants []*interactive_signing.Cosigner[C, P, F, S, V, M], message M) (partialSignatures []*tschnorr.PartialSignature[P, F, S]) {
	r2bi := DoRound1(tb, participants)
	r3bi := DoRound2(tb, participants, r2bi)
	partialSignatures = DoRound3(tb, participants, r3bi, message)
	return partialSignatures
}
