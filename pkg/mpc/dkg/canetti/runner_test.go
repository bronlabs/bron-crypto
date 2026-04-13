package canetti_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/canetti"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/hierarchical"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
)

func TestHappyPathRunner(t *testing.T) {
	t.Parallel()

	shareholders := sharing.NewOrdinalShareholderSet(4)
	thresholdAS, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)
	hierarchyAS, err := hierarchical.NewHierarchicalConjunctiveThresholdAccessStructure(
		hierarchical.WithLevel(1, sharing.ID(1), sharing.ID(2)),
		hierarchical.WithLevel(2, sharing.ID(3), sharing.ID(4)),
	)
	require.NoError(t, err)
	testAccessStructures := []accessstructures.Monotone{thresholdAS, hierarchyAS}

	for _, as := range testAccessStructures {
		t.Run("access structure", func(t *testing.T) {
			t.Parallel()

			t.Run("k256", func(t *testing.T) {
				t.Parallel()
				testHappyPathRunner(t, k256.NewCurve(), as)
			})
			t.Run("curve25519", func(t *testing.T) {
				t.Parallel()
				testHappyPathRunner(t, curve25519.NewPrimeSubGroup(), as)
			})
		})
	}
}

func testHappyPathRunner[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](t *testing.T, group algebra.PrimeGroup[G, S], accessStructure accessstructures.Monotone) {
	t.Helper()

	var err error
	prng := pcg.NewRandomised()
	quorum := accessStructure.Shareholders()
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)
	runners := make(map[sharing.ID]network.Runner[*mpc.BaseShard[G, S]])
	for id := range quorum.Iter() {
		runners[id], err = canetti.NewRunner(ctxs[id], accessStructure, group, pcg.NewRandomised())
		require.NoError(t, err)
	}
	shards := ntu.TestExecuteRunners(t, runners)

	t.Run("public materials are consistent", func(t *testing.T) {
		t.Parallel()

		var commonVerificationVector *feldman.VerificationVector[G, S]
		for id := range quorum.Iter() {
			verificationVector := shards[id].VerificationVector()
			require.NotNil(t, verificationVector)

			if commonVerificationVector == nil {
				commonVerificationVector = verificationVector
			} else {
				require.True(t, commonVerificationVector.Equal(verificationVector))
			}
		}
	})

	t.Run("secret shares are consistent", func(t *testing.T) {
		t.Parallel()

		var secret S
		scheme, err := feldman.NewScheme(group, accessStructure)
		require.NoError(t, err)
		for ids := range sliceutils.KCoveringCombinations(quorum.List(), 1) {
			if accessStructure.IsQualified(ids...) {
				shares := sliceutils.Map(ids, func(id sharing.ID) *feldman.Share[S] { return shards[id].Share() })
				reconstructed, err := scheme.Reconstruct(shares...)
				require.NoError(t, err)
				if utils.IsNil(secret) {
					secret = reconstructed.Value()
				} else {
					require.True(t, secret.Equal(reconstructed.Value()))
				}
			}
		}
	})

	t.Run("transcripts are consistent", func(t *testing.T) {
		t.Parallel()

		tapeSamples := [][]byte{}
		for id := range quorum.Iter() {
			tape := ctxs[id].Transcript()
			tapeSample, err := tape.ExtractBytes("test", 32)
			require.NoError(t, err)
			tapeSamples = append(tapeSamples, tapeSample)
		}

		for s := 1; s < len(tapeSamples); s++ {
			require.True(t, bytes.Equal(tapeSamples[s-1], tapeSamples[s]))
		}
	})
}
