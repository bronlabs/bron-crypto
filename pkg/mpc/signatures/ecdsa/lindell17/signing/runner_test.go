package signing_test

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/lindell17/keygen/trusted_dealer"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/lindell17/signing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fischlin"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

func TestRunnerHappyPath_K256_2P(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()
	suite, err := ecdsa.NewSuite(curve, crypto.SHA256.New)
	require.NoError(t, err)

	shareholders := sharing.NewOrdinalShareholderSet(3)
	accessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)
	shards, publicKey, err := trusted_dealer.DealRandom(curve, accessStructure, 1024, prng)
	require.NoError(t, err)

	primaryID := sharing.ID(1)
	secondaryID := sharing.ID(2)
	primaryShard, ok := shards.Get(primaryID)
	require.True(t, ok)
	secondaryShard, ok := shards.Get(secondaryID)
	require.True(t, ok)
	primaryShard = ntu.CBORRoundTrip(t, primaryShard)
	secondaryShard = ntu.CBORRoundTrip(t, secondaryShard)

	ctxs := session_testutils.MakeRandomContexts(t, hashset.NewComparable(primaryID, secondaryID).Freeze(), prng)
	message := []byte("hello from lindell17 runner")

	primaryRunner, err := signing.NewPrimaryRunner(
		ctxs[primaryID],
		suite,
		secondaryID,
		primaryShard,
		fischlin.Name,
		pcg.NewRandomised(),
		message,
	)
	require.NoError(t, err)

	secondaryRunner, err := signing.NewSecondaryRunner(
		ctxs[secondaryID],
		suite,
		primaryID,
		secondaryShard,
		fischlin.Name,
		pcg.NewRandomised(),
		message,
	)
	require.NoError(t, err)

	runners := map[sharing.ID]network.Runner[*ecdsa.Signature[*k256.Scalar]]{
		primaryID:   primaryRunner,
		secondaryID: secondaryRunner,
	}
	outputs, notifications := ntu.TestExecuteRunners(t, runners)
	require.Len(t, outputs, 2)
	requireRoundNotifications(t, notifications[primaryID], 1, 3, 5)
	requireRoundNotifications(t, notifications[secondaryID], 2, 4)

	signature, ok := outputs[primaryID]
	require.True(t, ok)
	require.NotNil(t, signature)

	secondaryOut, ok := outputs[secondaryID]
	require.True(t, ok)
	require.Nil(t, secondaryOut)

	verifier, err := ecdsa.NewVerifier(suite)
	require.NoError(t, err)
	err = verifier.Verify(signature, publicKey, message)
	require.NoError(t, err)

	primaryTapeCheck, err := ctxs[primaryID].Transcript().ExtractBytes("test", 32)
	require.NoError(t, err)
	secondaryTapeCheck, err := ctxs[secondaryID].Transcript().ExtractBytes("test", 32)
	require.NoError(t, err)
	require.True(t, bytes.Equal(primaryTapeCheck, secondaryTapeCheck))
}

func requireRoundNotifications(t *testing.T, notifications []network.Notification, rounds ...int) {
	t.Helper()
	require.Len(t, notifications, len(rounds))
	for i, notification := range notifications {
		roundCompleted, ok := notification.(*network.RoundCompletedNotification)
		require.True(t, ok)
		require.Equal(t, signing.ProtocolName, roundCompleted.ProtocolName())
		require.Equal(t, rounds[i], roundCompleted.Round())
		require.False(t, roundCompleted.Timestamp().IsZero())
	}
}
