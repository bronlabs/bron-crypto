package dkg_test

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	baseprng "github.com/bronlabs/bron-crypto/pkg/base/prng"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/trusteddealer"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21/keygen/dkg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21/signing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	sigecdsa "github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

// TestSubsetRunnerSigning runs the aux-info protocol among a qualified
// two-party subset of a 2-of-3 base sharing and then signs with the resulting
// subset shards in a fresh session, verifying the signature against the full
// sharing's public key. It also pins the persistence guard: a subset shard
// must not survive a serialisation round-trip.
func TestSubsetRunnerSigning(t *testing.T) {
	t.Parallel()

	type shard = *cggmp21.Shard[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]

	group := k256.NewCurve()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	accessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	prng := pcg.NewRandomised()
	dealt, err := trusteddealer.Deal(group, accessStructure, prng)
	require.NoError(t, err)

	quorum := hashset.NewComparable[sharing.ID](1, 2).Freeze()
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)

	runners := make(map[sharing.ID]network.Runner[shard])
	for id := range quorum.Iter() {
		bs, ok := dealt.Get(id)
		require.True(t, ok)
		runners[id], err = dkg.NewSubsetRunner[*k256.Point, *k256.BaseFieldElement, *k256.Scalar](ctxs[id], bs, baseprng.NewThreadSafeReader(pcg.NewRandomised()))
		require.NoError(t, err)
	}

	shards, notifications := ntu.TestExecuteRunners(t, runners)
	require.Len(t, shards, quorum.Size())
	ntu.RequireRoundCompletedNotifications(t, notifications, quorum, dkg.ProtocolName, 4)

	for id := range quorum.Iter() {
		require.NotNil(t, shards[id])
		require.Len(t, shards[id].AuxInfo().PaillierPublicKeys(), quorum.Size()-1)
		require.Len(t, shards[id].AuxInfo().RingPedersenPublicKeys(), quorum.Size()-1)
	}

	t.Run("subset shard does not survive a serialisation round-trip", func(t *testing.T) {
		for id := range quorum.Iter() {
			data, err := shards[id].MarshalCBOR()
			require.NoError(t, err)
			decoded := new(cggmp21.Shard[*k256.Point, *k256.BaseFieldElement, *k256.Scalar])
			require.Error(t, decoded.UnmarshalCBOR(data))
		}
	})

	suite, err := sigecdsa.NewSuite(group, sha256.New)
	require.NoError(t, err)
	message := []byte("hello from an ephemeral cggmp21 subset")
	signCtxs := session_testutils.MakeRandomContexts(t, quorum, prng)

	signRunners := make(map[sharing.ID]network.Runner[*signing.SignResult[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]])
	for id := range quorum.Iter() {
		signRunners[id], err = signing.NewRunner(signCtxs[id], suite, shards[id], message, pcg.NewRandomised())
		require.NoError(t, err)
	}

	results, signNotifications := ntu.TestExecuteRunners(t, signRunners)
	require.Len(t, results, quorum.Size())
	ntu.RequireRoundCompletedNotifications(t, signNotifications, quorum, signing.ProtocolName, 4)

	verifier, err := sigecdsa.NewVerifier(suite)
	require.NoError(t, err)

	partialSignatures := make(map[sharing.ID]*cggmp21.PartialSignature[*k256.Point, *k256.BaseFieldElement, *k256.Scalar])
	for id, result := range results {
		require.NotNil(t, result)
		require.NotNil(t, result.PartialSignature())
		require.NotNil(t, result.PartialSignatureCosigningAggregator())
		partialSignatures[id] = result.PartialSignature()
	}

	var expected *sigecdsa.Signature[*k256.Scalar]
	for id := range quorum.Iter() {
		result, ok := results[id]
		require.True(t, ok)
		signature, err := result.PartialSignatureCosigningAggregator().Aggregate(partialSignatures)
		require.NoError(t, err)
		require.NoError(t, verifier.Verify(signature, shards[id].PublicKey(), message))
		if expected == nil {
			expected = signature
		} else {
			require.True(t, expected.Equal(signature))
		}
	}
}

// TestNewSubsetParticipantValidation covers the subset constructor's quorum
// checks. None of these reach the (expensive) key generation in Round1.
func TestNewSubsetParticipantValidation(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	accessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)
	prng := pcg.NewRandomised()
	dealt, err := trusteddealer.Deal(group, accessStructure, prng)
	require.NoError(t, err)
	bs, ok := dealt.Get(sharing.ID(1))
	require.True(t, ok)

	t.Run("unqualified subset", func(t *testing.T) {
		t.Parallel()
		wideShareholders := sharing.NewOrdinalShareholderSet(4)
		wideAS, err := threshold.NewThresholdAccessStructure(3, wideShareholders)
		require.NoError(t, err)
		wideDealt, err := trusteddealer.Deal(group, wideAS, pcg.NewRandomised())
		require.NoError(t, err)
		wideBS, ok := wideDealt.Get(sharing.ID(1))
		require.True(t, ok)
		pair := hashset.NewComparable[sharing.ID](1, 2).Freeze()
		ctxs := session_testutils.MakeRandomContexts(t, pair, pcg.NewRandomised())
		_, err = dkg.NewSubsetParticipant[*k256.Point, *k256.BaseFieldElement, *k256.Scalar](ctxs[1], wideBS, prng)
		require.True(t, errs.Is(err, cggmp21.ErrValidationFailed))
	})

	t.Run("quorum member outside the shareholder set", func(t *testing.T) {
		t.Parallel()
		outside := hashset.NewComparable[sharing.ID](1, 4).Freeze()
		ctxs := session_testutils.MakeRandomContexts(t, outside, pcg.NewRandomised())
		_, err := dkg.NewSubsetParticipant[*k256.Point, *k256.BaseFieldElement, *k256.Scalar](ctxs[1], bs, prng)
		require.True(t, errs.Is(err, cggmp21.ErrValidationFailed))
	})

	t.Run("full quorum is accepted", func(t *testing.T) {
		t.Parallel()
		ctxs := session_testutils.MakeRandomContexts(t, shareholders, pcg.NewRandomised())
		_, err := dkg.NewSubsetParticipant[*k256.Point, *k256.BaseFieldElement, *k256.Scalar](ctxs[1], bs, prng)
		require.NoError(t, err)
	})
}
