package testutils

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/recovery"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig"
	"github.com/stretchr/testify/require"
)

func MakeRunners(tb testing.TB, ac *sharing.ThresholdAccessStructure, mislayerID sharing.ID) (mislayerShard *tsig.BaseShard[*k256.Point, *k256.Scalar], mislayers map[sharing.ID]network.Runner[*recovery.Output[*k256.Point, *k256.Scalar]], recoverers map[sharing.ID]network.Runner[any]) {
	tb.Helper()
	prng := pcg.NewRandomised()

	group := k256.NewCurve()
	scheme, err := feldman.NewScheme(group.Generator(), ac)
	require.NoError(tb, err)
	dealerOutput, _, err := scheme.DealRandom(prng)
	require.NoError(tb, err)
	verificationVector := dealerOutput.VerificationMaterial()

	mislayerShare, ok := dealerOutput.Shares().Get(mislayerID)
	require.True(tb, ok)
	mislayerShard, err = tsig.NewBaseShard(mislayerShare, verificationVector, ac)
	require.NoError(tb, err)
	mislayerRunner, err := recovery.NewMislayerRunner(mislayerID, ac.Shareholders(), ac, group)
	require.NoError(tb, err)
	mislayers = make(map[sharing.ID]network.Runner[*recovery.Output[*k256.Point, *k256.Scalar]])
	mislayers[mislayerID] = mislayerRunner

	recoverers = make(map[sharing.ID]network.Runner[any], 0)
	for id := range ac.Shareholders().Iter() {
		if id == mislayerID {
			continue
		}

		share, ok := dealerOutput.Shares().Get(id)
		require.True(tb, ok)
		shard, err := tsig.NewBaseShard(share, verificationVector, ac)
		require.NoError(tb, err)
		runner, err := recovery.NewRecovererRunner(mislayerID, ac.Shareholders(), shard, prng)
		require.NoError(tb, err)
		recoverers[id] = runner
	}

	return mislayerShard, mislayers, recoverers
}
