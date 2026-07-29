package dkg_test

import (
	"maps"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/trusteddealer"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/cnf"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/lindell17/keygen/dkg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/lindell17/keygen/dkg/testutils"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
)

func TestLindell17DKG_K256_2of3(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	accessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	shards := testutils.RunLindell17DKG(t, curve, accessStructure)
	require.Len(t, shards, shareholders.Size())
	for id, shard := range shards {
		require.NotNil(t, shard.PaillierSecretKey(), "shard %d", id)
		require.Equal(t, shareholders.Size()-1, shard.PaillierPublicKeys().Size(), "shard %d", id)
		require.Equal(t, shareholders.Size()-1, shard.EncryptedShares().Size(), "shard %d", id)
	}
}

func TestLindell17DKG_P256_2of2(t *testing.T) {
	t.Parallel()

	curve := p256.NewCurve()
	shareholders := sharing.NewOrdinalShareholderSet(2)
	accessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	shards := testutils.RunLindell17DKG(t, curve, accessStructure)
	require.Len(t, shards, shareholders.Size())
}

func TestLindell17DKG_K256_CNFEquivalent2of3(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	thresholdAccessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)
	accessStructure, err := cnf.ConvertToCNF(thresholdAccessStructure)
	require.NoError(t, err)

	shards := testutils.RunLindell17DKG(t, curve, accessStructure)
	require.Len(t, shards, shareholders.Size())
	for id, shard := range shards {
		require.Greater(t, len(shard.Share().Value()), 1, "CNF share for shareholder %d must be non-ideal", id)
		require.Equal(t, shareholders.Size()-1, shard.EncryptedShares().Size())
	}
}

func TestLindell17DKG_K256_3of3StoresNoUnqualifiedPairs(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	accessStructure, err := threshold.NewThresholdAccessStructure(3, shareholders)
	require.NoError(t, err)

	shards := testutils.RunLindell17DKG(t, curve, accessStructure)
	require.Len(t, shards, shareholders.Size())
	for _, shard := range shards {
		require.Zero(t, shard.PaillierPublicKeys().Size())
		require.Zero(t, shard.EncryptedShares().Size())
	}
}

func TestRound2BroadcastRejectsMalformedComponentData(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	thresholdAccessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)
	accessStructure, err := cnf.ConvertToCNF(thresholdAccessStructure)
	require.NoError(t, err)

	prng := pcg.NewRandomised()
	baseShards, err := trusteddealer.Deal(curve, accessStructure, prng)
	require.NoError(t, err)
	contexts := session_testutils.MakeRandomContexts(t, shareholders, prng)
	participants := make(map[sharing.ID]*dkg.Participant[*k256.Point, *k256.BaseFieldElement, *k256.Scalar], shareholders.Size())
	participantList := make([]*dkg.Participant[*k256.Point, *k256.BaseFieldElement, *k256.Scalar], 0, shareholders.Size())
	for id := range shareholders.Iter() {
		baseShard, ok := baseShards.Get(id)
		require.True(t, ok)
		participant, err := dkg.NewParticipant(
			contexts[id],
			baseShard,
			1024,
			curve,
			pcg.NewRandomised(),
			fiatshamir.Name,
		)
		require.NoError(t, err)
		participants[id] = participant
		participantList = append(participantList, participant)
	}

	round1Outputs := make(map[sharing.ID]*dkg.Round1Broadcast[*k256.Point, *k256.BaseFieldElement, *k256.Scalar], shareholders.Size())
	for id, participant := range participants {
		round1Outputs[id], err = participant.Round1()
		require.NoError(t, err)
	}
	round2Inputs := ntu.MapBroadcastO2I(t, participantList, round1Outputs)
	round2Outputs := make(map[sharing.ID]*dkg.Round2Broadcast[*k256.Point, *k256.BaseFieldElement, *k256.Scalar], shareholders.Size())
	for id, participant := range participants {
		round2Outputs[id], err = participant.Round2(round2Inputs[id])
		require.NoError(t, err)
	}
	round2Output := round2Outputs[1]
	require.Greater(t, len(round2Output.Components), 1)

	tampered := *round2Output
	tampered.Components = append([]*dkg.ComponentDecomposition[*k256.Point, *k256.BaseFieldElement, *k256.Scalar](nil), round2Output.Components...)
	tampered.Components[0], tampered.Components[1] = tampered.Components[1], tampered.Components[0]
	err = tampered.Validate(participants[2], 1)
	require.ErrorContains(t, err, "wrong MSP row identifier")

	tampered = *round2Output
	tampered.Components = append([]*dkg.ComponentDecomposition[*k256.Point, *k256.BaseFieldElement, *k256.Scalar](nil), round2Output.Components...)
	tamperedComponent := *tampered.Components[0]
	tamperedComponent.BigQPrimeProof = []byte{0xf6}
	tampered.Components[0] = &tamperedComponent
	tamperedOutputs := maps.Clone(round2Outputs)
	tamperedOutputs[1] = &tampered
	round3Inputs := ntu.MapBroadcastO2I(t, participantList, tamperedOutputs)
	require.NotPanics(t, func() {
		_, err = participants[2].Round3(round3Inputs[2])
	})
	require.ErrorIs(t, err, proofs.ErrInvalidArgument)
	require.ErrorContains(t, err, "cannot verify Q' discrete-log proof")
}

func TestNewParticipantRejectsPartialMSPQuorum(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	accessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)
	baseShards, err := trusteddealer.Deal(curve, accessStructure, pcg.NewRandomised())
	require.NoError(t, err)
	baseShard, ok := baseShards.Get(1)
	require.True(t, ok)

	partialQuorum := sharing.NewOrdinalShareholderSet(2)
	ctxs := session_testutils.MakeRandomContexts(t, partialQuorum, pcg.NewRandomised())
	_, err = dkg.NewParticipant(
		ctxs[1],
		baseShard,
		1024,
		curve,
		pcg.NewRandomised(),
		fiatshamir.Name,
	)
	require.ErrorContains(t, err, "context quorum must equal the MSP shareholder set")
}
