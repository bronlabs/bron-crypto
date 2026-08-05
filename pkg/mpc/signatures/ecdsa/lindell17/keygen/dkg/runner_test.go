package dkg_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/trusteddealer"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/lindell17"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/lindell17/keygen/dkg"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
)

func TestRunnerHappyPath_K256_2of2(t *testing.T) {
	t.Parallel()

	type shard = *lindell17.Shard[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]

	const paillierKeyLen = 1024
	curve := k256.NewCurve()
	shareholders := sharing.NewOrdinalShareholderSet(2)
	accessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	prng := pcg.NewRandomised()
	baseShards, err := trusteddealer.Deal(curve, accessStructure, prng)
	require.NoError(t, err)
	ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)
	runners := make(map[sharing.ID]network.Runner[shard], shareholders.Size())
	for id := range shareholders.Iter() {
		baseShard, ok := baseShards.Get(id)
		require.True(t, ok)
		runners[id], err = dkg.NewRunner(
			ctxs[id],
			baseShard,
			paillierKeyLen,
			curve,
			pcg.NewRandomised(),
			fiatshamir.Name,
		)
		require.NoError(t, err)
	}

	outputs, notifications := ntu.TestExecuteRunners(t, runners)
	require.Len(t, outputs, shareholders.Size())
	ids := shareholders.List()
	referencePublicKey := outputs[ids[0]].PublicKeyValue()
	for _, id := range ids {
		require.NotNil(t, outputs[id])
		require.True(t, referencePublicKey.Equal(outputs[id].PublicKeyValue()))
		require.Equal(t, shareholders.Size()-1, outputs[id].PaillierPublicKeys().Size())
		require.Equal(t, shareholders.Size()-1, outputs[id].EncryptedShares().Size())
	}
	ntu.RequireRoundCompletedNotifications(t, notifications, shareholders, dkg.ProtocolName, 8)
}
