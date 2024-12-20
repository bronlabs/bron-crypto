package riss_batch_mul_test

import (
	crand "crypto/rand"
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/riss"
	rissBatchMul "github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/riss/protocols/batch_mul"
	rissSeedSetup "github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/riss/protocols/seed_setup"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"
	"io"
	"math/big"
	"testing"
)

var accessStructures = []struct{ th, n uint }{
	{th: 2, n: 3},
	{th: 2, n: 4},
	{th: 3, n: 5},
	{th: 3, n: 7},
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	const bitLen = 2048
	const batch = 128
	prng := crand.Reader

	for _, as := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", as.th, as.n), func(t *testing.T) {
			t.Parallel()

			identities, err := testutils.MakeDeterministicTestIdentities(int(as.n))
			require.NoError(t, err)
			tapes := make([]transcripts.Transcript, as.n)
			for i := range tapes {
				tapes[i] = hagrid.NewTranscript("test", nil)
			}

			seeds := runSeedSetup(t, as.th, identities, tapes, prng)
			lhs := make([][]*riss.IntShare, as.n)
			rhs := make([][]*riss.IntShare, as.n)
			for i := range as.n {
				lhs[i] = make([]*riss.IntShare, batch)
				rhs[i] = make([]*riss.IntShare, batch)
				for k := range batch {
					lhs[i][k], err = seeds[i].Sample(riss.WithBitLen(bitLen))
					require.NoError(t, err)
					rhs[i][k], err = seeds[i].Sample(riss.WithBitLen(bitLen))
					require.NoError(t, err)
				}
			}

			dealer, err := riss.NewDealer(as.th, as.n, riss.WithBitLen(bitLen))
			require.NoError(t, err)
			expected := make([]*big.Int, batch)
			for k := range batch {
				var lShares []*riss.IntShare
				for i := range as.n {
					lShares = append(lShares, lhs[i][k])
				}
				var rShares []*riss.IntShare
				for i := range as.n {
					rShares = append(rShares, rhs[i][k])
				}
				l, err := dealer.Open(lShares...)
				require.NoError(t, err)
				r, err := dealer.Open(rShares...)
				require.NoError(t, err)
				expected[k] = new(big.Int).Mul(l, r)
			}

			resultShares := runBatchMul(t, as.th, identities, tapes, seeds, prng, lhs, rhs, riss.WithBitLen(2*bitLen))
			result := make([]*big.Int, batch)
			for k := range batch {
				var shares []*riss.IntShare
				for i := range as.n {
					shares = append(shares, resultShares[i][k])
				}
				result[k], err = dealer.Open(shares...)
				require.NoError(t, err)
			}

			for k := range batch {
				require.Zero(t, result[k].Cmp(expected[k]))
			}
		})
	}
}

func Test_HappyPathMod(t *testing.T) {
	t.Parallel()
	const modulusLen = 2048
	const batch = 128
	prng := crand.Reader
	modulusBound := new(big.Int)
	modulusBound.SetBit(modulusBound, modulusLen, 1)
	modulus, err := crand.Int(prng, modulusBound)
	require.NoError(t, err)

	for _, as := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", as.th, as.n), func(t *testing.T) {
			t.Parallel()

			identities, err := testutils.MakeDeterministicTestIdentities(int(as.n))
			require.NoError(t, err)
			tapes := make([]transcripts.Transcript, as.n)
			for i := range tapes {
				tapes[i] = hagrid.NewTranscript("test", nil)
			}

			seeds := runSeedSetup(t, as.th, identities, tapes, prng)
			lhs := make([][]*riss.IntShare, as.n)
			rhs := make([][]*riss.IntShare, as.n)
			for i := range as.n {
				lhs[i] = make([]*riss.IntShare, batch)
				rhs[i] = make([]*riss.IntShare, batch)
				for k := range batch {
					lhs[i][k], err = seeds[i].Sample(riss.WithModulus(modulus))
					require.NoError(t, err)
					rhs[i][k], err = seeds[i].Sample(riss.WithModulus(modulus))
					require.NoError(t, err)
				}
			}

			dealer, err := riss.NewDealer(as.th, as.n, riss.WithModulus(modulus))
			require.NoError(t, err)
			expected := make([]*big.Int, batch)
			for k := range batch {
				var lShares []*riss.IntShare
				for i := range as.n {
					lShares = append(lShares, lhs[i][k])
				}
				var rShares []*riss.IntShare
				for i := range as.n {
					rShares = append(rShares, rhs[i][k])
				}
				l, err := dealer.Open(lShares...)
				require.NoError(t, err)
				r, err := dealer.Open(rShares...)
				require.NoError(t, err)
				expected[k] = new(big.Int).Mul(l, r)
				expected[k].Mod(expected[k], modulus)
			}

			productsShares := runBatchMul(t, as.th, identities, tapes, seeds, prng, lhs, rhs, riss.WithModulus(modulus))
			result := make([]*big.Int, batch)
			for k := range batch {
				var shares []*riss.IntShare
				for i := range as.n {
					shares = append(shares, productsShares[i][k])
				}
				result[k], err = dealer.Open(shares...)
				require.NoError(t, err)
			}

			for k := range batch {
				require.Zero(t, result[k].Cmp(expected[k]))
			}
		})
	}
}

func runSeedSetup(tb testing.TB, threshold uint, identities []types.IdentityKey, tapes []transcripts.Transcript, prng io.Reader) []*riss.PseudoRandomSeed {
	tb.Helper()

	protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, int(threshold))
	require.NoError(tb, err)

	participants := make([]*rissSeedSetup.Participant, len(identities))
	for i := range participants {
		participants[i], err = rissSeedSetup.NewParticipant(identities[i], protocol, tapes[i], prng)
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

func runBatchMul(tb testing.TB, threshold uint, identities []types.IdentityKey, tapes []transcripts.Transcript, seeds []*riss.PseudoRandomSeed, prng io.Reader, lhs, rhs [][]*riss.IntShare, opts ...riss.SharingOpt) [][]*riss.IntShare {
	tb.Helper()

	protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, int(threshold))
	require.NoError(tb, err)

	participants := make([]*rissBatchMul.Participant, len(identities))
	for i := range participants {
		participants[i], err = rissBatchMul.NewParticipant(identities[i], protocol, tapes[i], prng, seeds[i], opts...)
		require.NoError(tb, err)
	}

	r1Out := make([]network.RoundMessages[types.ThresholdProtocol, *rissBatchMul.Round1P2P], len(participants))
	for i, party := range participants {
		r1Out[i], err = party.Round1(lhs[i], rhs[i])
		require.NoError(tb, err)
	}

	r2In := testutils.MapUnicastO2I(tb, participants, r1Out)
	results := make([][]*riss.IntShare, len(participants))
	for i, party := range participants {
		results[i], err = party.Round2(r2In[i])
		require.NoError(tb, err)
	}

	return results
}
