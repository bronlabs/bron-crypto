package riss_seed_setup_test

import (
	crand "crypto/rand"
	"fmt"
	"io"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/combinatorics"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/riss"
	rissSeedSetup "github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/riss/protocols/seed_setup"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const iters = 128

var accessStructures = []struct{ th, n uint }{
	{th: 2, n: 3},
	{th: 2, n: 4},
	{th: 3, n: 5},
	{th: 3, n: 7},
	{th: 5, n: 10},
}

func Test_HappyPathRange(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	low := big.NewInt(123_456)
	high := big.NewInt(124_789)

	for _, ac := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", ac.th, ac.n), func(t *testing.T) {
			t.Parallel()

			for range iters {
				seeds := runSeedSetup(t, ac.th, ac.n, prng)
				require.Len(t, seeds, int(ac.n))
				for _, seed := range seeds {
					testingTh, testingN := seed.ThresholdAccessStructure()
					require.Equal(t, ac.th, testingTh)
					require.Equal(t, ac.n, testingN)
				}

				dealer, err := riss.NewDealer(ac.th, ac.n, riss.WithBitLen(uint(2048)))
				require.NoError(t, err)

				shares := make([]*riss.IntShare, len(seeds))
				for i, seed := range seeds {
					shares[i], err = seed.Sample(riss.WithRange(low, high))
					require.NoError(t, err)

					testThreshold, testTotal := shares[i].ThresholdAccessStructure()
					require.Equal(t, ac.th, testThreshold)
					require.Equal(t, ac.n, testTotal)
				}

				for shareCount := ac.th; shareCount <= ac.n; shareCount++ {
					combinations, err := combinatorics.Combinations(shares, shareCount)
					require.NoError(t, err)

					results := []*big.Int{}
					for _, combination := range combinations {
						revealed, err := dealer.Open(combination...)
						require.NoError(t, err)
						require.Positive(t, revealed.Cmp(low))
						require.Negative(t, revealed.Cmp(high))
						results = append(results, revealed)
					}
					for i := 1; i < len(results); i++ {
						require.True(t, results[i-1].Cmp(results[i]) == 0)
					}
				}

				for shareCount := 0; shareCount < int(ac.th); shareCount++ {
					combinations, err := combinatorics.Combinations(shares, uint(shareCount))
					require.NoError(t, err)

					for _, combination := range combinations {
						_, err := dealer.Open(combination...)
						require.Error(t, err)
					}
				}
			}
		})
	}
}

func Test_HappyPathBitLen(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	bitLen := 2048

	for _, ac := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", ac.th, ac.n), func(t *testing.T) {
			t.Parallel()

			for range iters {
				seeds := runSeedSetup(t, ac.th, ac.n, prng)
				require.Len(t, seeds, int(ac.n))
				for _, seed := range seeds {
					testingTh, testingN := seed.ThresholdAccessStructure()
					require.Equal(t, ac.th, testingTh)
					require.Equal(t, ac.n, testingN)
				}

				dealer, err := riss.NewDealer(ac.th, ac.n, riss.WithBitLen(uint(bitLen)))
				require.NoError(t, err)

				shares := make([]*riss.IntShare, len(seeds))
				for i, seed := range seeds {
					shares[i], err = seed.Sample(riss.WithBitLen(uint(bitLen)))
					require.NoError(t, err)

					testThreshold, testTotal := shares[i].ThresholdAccessStructure()
					require.Equal(t, ac.th, testThreshold)
					require.Equal(t, ac.n, testTotal)
				}

				for shareCount := ac.th; shareCount <= ac.n; shareCount++ {
					combinations, err := combinatorics.Combinations(shares, shareCount)
					require.NoError(t, err)

					results := []*big.Int{}
					for _, combination := range combinations {
						revealed, err := dealer.Open(combination...)
						require.NoError(t, err)
						require.Equal(t, revealed.BitLen(), bitLen)
						results = append(results, revealed)
					}
					for i := 1; i < len(results); i++ {
						require.True(t, results[i-1].Cmp(results[i]) == 0)
					}
				}

				for shareCount := 0; shareCount < int(ac.th); shareCount++ {
					combinations, err := combinatorics.Combinations(shares, uint(shareCount))
					require.NoError(t, err)

					for _, combination := range combinations {
						_, err := dealer.Open(combination...)
						require.Error(t, err)
					}
				}
			}
		})
	}
}

func runSeedSetup(tb testing.TB, threshold, total uint, prng io.Reader) []*riss.PseudoRandomSeed {
	tb.Helper()

	identities, err := testutils.MakeDeterministicTestIdentities(int(total))
	require.NoError(tb, err)
	protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, int(threshold))
	require.NoError(tb, err)

	participants := make([]*rissSeedSetup.Participant, total)
	for i := range participants {
		tape := hagrid.NewTranscript("test", nil)
		participants[i], err = rissSeedSetup.NewParticipant(identities[i], protocol, tape, prng)
		require.NoError(tb, err)
	}

	r1Out := make([]network.RoundMessages[types.ThresholdProtocol, *rissSeedSetup.Round1P2P], len(participants))
	for i, party := range participants {
		r1Out[i] = party.Round1()
	}

	r2In := testutils.MapUnicastO2I(tb, participants, r1Out)
	seeds := make([]*riss.PseudoRandomSeed, len(participants))
	for i, party := range participants {
		seeds[i] = party.Round2(r2In[i])
	}

	return seeds
}
