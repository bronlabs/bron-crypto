package trusted_dealer_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/dkls23/keygen/trusted_dealer"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	const THRESHOLD = 3
	const TOTAL = 5
	prng := pcg.NewRandomised()
	curve := k256.NewCurve()
	shareholders := hashset.NewComparable[sharing.ID]()
	for i := range TOTAL {
		shareholders.Add(sharing.ID(i + 1))
	}

	shards, pk, err := trusted_dealer.DealRandom(curve, THRESHOLD, shareholders.Freeze(), prng)
	require.NoError(t, err)
	ac, err := accessstructures.NewThresholdAccessStructure(THRESHOLD, shareholders.Freeze())
	require.NoError(t, err)

	t.Run("shares match", func(t *testing.T) {
		t.Parallel()
		for th := uint(THRESHOLD); th <= TOTAL; th++ {
			for shardsSubset := range sliceutils.Combinations(shards.Values(), th) {
				feldmanScheme, err := feldman.NewScheme(curve.Generator(), ac)
				require.NoError(t, err)
				sharesSubset := sliceutils.Map(shardsSubset, func(s *dkls23.Shard[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]) *feldman.Share[*k256.Scalar] {
					return s.Share()
				})
				recoveredSk, err := feldmanScheme.Reconstruct(sharesSubset...)
				require.NoError(t, err)

				recoveredPk := curve.ScalarBaseMul(recoveredSk.Value())
				require.True(t, recoveredPk.Equal(pk.Value()))
			}
		}
	})

	t.Run("zero seeds match", func(t *testing.T) {
		t.Parallel()
		for me := sharing.ID(1); me <= TOTAL; me++ {
			for they := sharing.ID(1); they <= TOTAL; they++ {
				if me == they {
					continue
				}
				myShard, ok := shards.Get(me)
				require.True(t, ok)
				theirShard, ok := shards.Get(they)
				require.True(t, ok)
				mySeed, ok := myShard.ZeroSeeds().Get(they)
				require.True(t, ok)
				theirSeed, ok := theirShard.ZeroSeeds().Get(me)
				require.True(t, ok)
				require.Equal(t, mySeed, theirSeed)
			}
		}
	})

	t.Run("OT seeds match", func(t *testing.T) {
		t.Parallel()
		for s := sharing.ID(1); s <= TOTAL; s++ {
			for r := sharing.ID(1); r <= TOTAL; r++ {
				if s == r {
					continue
				}

				senderShard, ok := shards.Get(s)
				require.True(t, ok)
				senderSeeds, ok := senderShard.OTSenderSeeds().Get(r)
				require.True(t, ok)
				receiverShard, ok := shards.Get(r)
				require.True(t, ok)
				receiverSeeds, ok := receiverShard.OTReceiverSeeds().Get(s)
				require.True(t, ok)

				require.Len(t, senderSeeds.Messages, softspoken.Kappa)
				require.Len(t, receiverSeeds.Messages, softspoken.Kappa)
				for k := range softspoken.Kappa {
					require.Len(t, senderSeeds.Messages[k][0], 1)
					require.Len(t, senderSeeds.Messages[k][1], 1)
					require.Len(t, receiverSeeds.Messages[k], 1)

					c := (receiverSeeds.Choices[k/8] >> (k % 8)) & 0b1
					require.Equal(t, senderSeeds.Messages[k][c][0], receiverSeeds.Messages[k][0])
				}
			}
		}
	})
}
