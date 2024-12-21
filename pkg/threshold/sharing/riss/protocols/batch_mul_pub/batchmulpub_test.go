package riss_batch_mul_pub_test

import (
	crand "crypto/rand"
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/riss"
	rissBatchMulPub "github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/riss/protocols/batch_mul_pub"
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

			products := runBatchMulPub(t, as.th, identities, tapes, seeds, prng, lhs, rhs, riss.WithBitLen(2*bitLen))
			for i := range as.n {
				for k := range batch {
					require.Zero(t, products[i][k].Cmp(expected[k]))
				}
			}
		})
	}
}

func Test_HappyPathMod(t *testing.T) {
	t.Parallel()
	const batch = 128
	prng := crand.Reader
	modulusBound := new(big.Int)
	modulusBound.SetBit(modulusBound, 2048, 1)
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

			product := runBatchMulPub(t, as.th, identities, tapes, seeds, prng, lhs, rhs, riss.WithModulus(modulus))
			for i := range as.n {
				for k := range batch {
					require.Zero(t, product[i][k].Cmp(expected[k]))
				}
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

func runBatchMulPub(tb testing.TB, threshold uint, identities []types.IdentityKey, tapes []transcripts.Transcript, seeds []*riss.PseudoRandomSeed, prng io.Reader, lhs, rhs [][]*riss.IntShare, opts ...riss.SharingOpt) [][]*big.Int {
	tb.Helper()

	protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, int(threshold))
	require.NoError(tb, err)

	participants := make([]*rissBatchMulPub.Participant, len(identities))
	for i := range participants {
		participants[i], err = rissBatchMulPub.NewParticipant(identities[i], protocol, tapes[i], prng, seeds[i], opts...)
		require.NoError(tb, err)
	}

	r1Out := make([]network.RoundMessages[types.ThresholdProtocol, *rissBatchMulPub.Round1P2P], len(participants))
	for i, party := range participants {
		r1Out[i], err = party.Round1(lhs[i], rhs[i])
		require.NoError(tb, err)
	}

	r2In := testutils.MapUnicastO2I(tb, participants, r1Out)
	results := make([][]*big.Int, len(participants))
	for i, party := range participants {
		results[i], err = party.Round2(r2In[i])
		require.NoError(tb, err)
	}

	return results
}
