package signing_test

import (
	"crypto/sha256"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21/keygen/trusteddealer"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21/signing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	sigecdsa "github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

func TestSigning_Threshold2Of3(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()
	keyLen := 2048
	shareholders := sharing.NewOrdinalShareholderSet(3)
	accessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	shards, err := trusteddealer.Deal(curve, accessStructure, keyLen, prng)
	require.NoError(t, err)
	require.Len(t, shards, 3)

	suite, err := sigecdsa.NewSuite(curve, sha256.New)
	require.NoError(t, err)
	message := []byte("hello from cggmp21 threshold signing")
	signingQuorum := hashset.NewComparable[sharing.ID](1, 2).Freeze()
	ctxs := session_testutils.MakeRandomContexts(t, signingQuorum, prng)

	runners := make(map[sharing.ID]network.Runner[*sigecdsa.Signature[*k256.Scalar]])
	for id := range signingQuorum.Iter() {
		shard, ok := shards[id]
		require.True(t, ok)
		runner, err := signing.NewRunner(ctxs[id], suite, shard, message, pcg.NewRandomised())
		require.NoError(t, err)
		runners[id] = runner
	}

	signatures, notifications := ntu.TestExecuteRunners(t, runners)
	require.Len(t, signatures, signingQuorum.Size())
	ntu.RequireRoundCompletedNotifications(t, notifications, signingQuorum, signing.ProtocolName, 4)

	verifier, err := sigecdsa.NewVerifier(suite)
	require.NoError(t, err)

	var expected *sigecdsa.Signature[*k256.Scalar]
	for id := range signingQuorum.Iter() {
		signature, ok := signatures[id]
		require.True(t, ok)
		require.NoError(t, verifier.Verify(signature, shards[1].PublicKey(), message))
		if expected == nil {
			expected = signature
		} else {
			require.True(t, expected.Equal(signature))
		}
	}

	var expectedTranscript []byte
	for id := range signingQuorum.Iter() {
		transcript, err := ctxs[id].Transcript().ExtractBytes("transcript consistency", 32)
		require.NoError(t, err)
		if expectedTranscript == nil {
			expectedTranscript = transcript
		} else {
			require.Equal(t, expectedTranscript, transcript)
		}
	}
}

func TestAggregateOffline_Threshold2Of3(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()
	keyLen := 2048
	shareholders := sharing.NewOrdinalShareholderSet(3)
	accessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	shards, err := trusteddealer.Deal(curve, accessStructure, keyLen, prng)
	require.NoError(t, err)
	require.Len(t, shards, 3)

	suite, err := sigecdsa.NewSuite(curve, sha256.New)
	require.NoError(t, err)
	message := []byte("hello from cggmp21 offline aggregation")
	signingIDs := []sharing.ID{1, 2}
	signingQuorum := hashset.NewComparable(signingIDs...).Freeze()
	ctxs := session_testutils.MakeRandomContexts(t, signingQuorum, prng)

	signers := make(map[sharing.ID]*signing.Signer[*k256.Point, *k256.BaseFieldElement, *k256.Scalar])
	for _, id := range signingIDs {
		shard, ok := shards[id]
		require.True(t, ok)
		signer, err := signing.NewSigner(ctxs[id], suite, shard, pcg.NewRandomised())
		require.NoError(t, err)
		signers[id] = signer
	}
	participants := slices.Collect(maps.Values(signers))

	r1bOut := make(map[sharing.ID]*signing.Round1Broadcast[*k256.Point, *k256.BaseFieldElement, *k256.Scalar])
	r1uOut := make(map[sharing.ID]network.OutgoingUnicasts[*signing.Round1P2P[*k256.Point, *k256.BaseFieldElement, *k256.Scalar], *signing.Signer[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]])
	for _, id := range signingIDs {
		r1bOut[id], r1uOut[id], err = signers[id].Round1()
		require.NoError(t, err)
	}

	r2bIn := ntu.MapBroadcastO2I(t, participants, r1bOut)
	r2uIn := ntu.MapUnicastO2I(t, participants, r1uOut)
	r2bOut := make(map[sharing.ID]*signing.Round2Broadcast[*k256.Point, *k256.BaseFieldElement, *k256.Scalar])
	r2uOut := make(map[sharing.ID]network.OutgoingUnicasts[*signing.Round2P2P[*k256.Point, *k256.BaseFieldElement, *k256.Scalar], *signing.Signer[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]])
	for _, id := range signingIDs {
		r2bOut[id], r2uOut[id], err = signers[id].Round2(r2bIn[id], r2uIn[id])
		require.NoError(t, err)
	}

	r3bIn := ntu.MapBroadcastO2I(t, participants, r2bOut)
	r3uIn := ntu.MapUnicastO2I(t, participants, r2uOut)
	r3bOut := make(map[sharing.ID]*signing.Round3Broadcast[*k256.Point, *k256.BaseFieldElement, *k256.Scalar])
	for _, id := range signingIDs {
		r3bOut[id], err = signers[id].Round3(r3bIn[id], r3uIn[id])
		require.NoError(t, err)
	}

	r4bIn := ntu.MapBroadcastO2I(t, participants, r3bOut)
	partialSignatures := make(map[sharing.ID]*cggmp21.PartialSignature[*k256.Point, *k256.BaseFieldElement, *k256.Scalar])
	for _, id := range signingIDs {
		partialSignatures[id], err = signers[id].Round4(r4bIn[id], message)
		require.NoError(t, err)
	}

	signature, err := signing.AggregateOffline(
		ntu.CBORRoundTrip(t, partialSignatures[1]),
		ntu.CBORRoundTrip(t, partialSignatures[2]),
	)
	require.NoError(t, err)
	statefulSignature, err := signers[1].Aggregate(partialSignatures)
	require.NoError(t, err)
	require.True(t, statefulSignature.Equal(signature))

	verifier, err := sigecdsa.NewVerifier(suite)
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(signature, shards[1].PublicKey(), message))
}

func TestSignerErrorHandling(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()
	keyLen := 2048
	shareholders := sharing.NewOrdinalShareholderSet(3)
	accessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	shards, err := trusteddealer.Deal(curve, accessStructure, keyLen, prng)
	require.NoError(t, err)
	suite, err := sigecdsa.NewSuite(curve, sha256.New)
	require.NoError(t, err)
	signingQuorum := hashset.NewComparable[sharing.ID](1, 2).Freeze()
	ctxs := session_testutils.MakeRandomContexts(t, signingQuorum, prng)

	signer, err := signing.NewSigner(ctxs[1], suite, shards[1], pcg.NewRandomised())
	require.NoError(t, err)

	_, _, err = signer.Round2(
		hashmap.NewComparable[sharing.ID, *signing.Round1Broadcast[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]]().Freeze(),
		hashmap.NewComparable[sharing.ID, *signing.Round1P2P[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]]().Freeze(),
	)
	require.ErrorIs(t, err, signing.ErrInvalidRound)

	_, _, err = signer.Round1()
	require.NoError(t, err)

	_, _, err = signer.Round2(
		hashmap.NewComparable[sharing.ID, *signing.Round1Broadcast[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]]().Freeze(),
		hashmap.NewComparable[sharing.ID, *signing.Round1P2P[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]]().Freeze(),
	)
	require.Error(t, err)
	require.Contains(t, errs.HasTagAll(err, base.IdentifiableAbortPartyIDTag), sharing.ID(2))
}
