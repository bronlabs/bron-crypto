package riss_mul_test

import (
	crand "crypto/rand"
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/riss"
	rissMul "github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/riss/protocols/mul"
	rissSeedSetup "github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/riss/protocols/seed_setup"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"
	"io"
	"math/big"
	"testing"
)

var accessStructures = []struct{ th, n, iters uint }{
	{th: 2, n: 3, iters: 128},
	{th: 2, n: 4, iters: 128},
	{th: 3, n: 5, iters: 128},
	{th: 3, n: 7, iters: 32},
	{th: 5, n: 10, iters: 8},
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	const bitLen = 2048
	prng := crand.Reader

	for _, as := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", as.th, as.n), func(t *testing.T) {
			t.Parallel()

			for range as.iters {
				identities, err := testutils.MakeDeterministicTestIdentities(int(as.n))
				require.NoError(t, err)
				tapes := make([]transcripts.Transcript, as.n)
				for i := range tapes {
					tapes[i] = hagrid.NewTranscript("test", nil)
				}

				seeds := runSeedSetup(t, as.th, identities, tapes, prng)
				lhs := make([]*riss.IntShare, as.n)
				rhs := make([]*riss.IntShare, as.n)
				for i := range as.n {
					lhs[i], err = seeds[i].Sample(riss.WithBitLen(bitLen))
					require.NoError(t, err)
					rhs[i], err = seeds[i].Sample(riss.WithBitLen(bitLen))
					require.NoError(t, err)
				}

				dealer, err := riss.NewDealer(as.th, as.n, riss.WithBitLen(bitLen))
				require.NoError(t, err)
				l, err := dealer.Open(lhs...)
				require.NoError(t, err)
				r, err := dealer.Open(rhs...)
				require.NoError(t, err)
				expected := new(big.Int).Mul(l, r)

				resultShares := runMulPub(t, as.th, identities, tapes, seeds, prng, lhs, rhs, riss.WithBitLen(2*bitLen))
				result, err := dealer.Open(resultShares...)
				require.NoError(t, err)
				require.Zero(t, result.Cmp(expected))
			}
		})
	}
}

func Test_HappyPathMod(t *testing.T) {
	t.Parallel()
	const modulusLen = 2048
	prng := crand.Reader
	modulusBound := new(big.Int)
	modulusBound.SetBit(modulusBound, modulusLen, 1)
	modulus, err := crand.Int(prng, modulusBound)
	require.NoError(t, err)

	for _, as := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", as.th, as.n), func(t *testing.T) {
			t.Parallel()

			for range as.iters {
				identities, err := testutils.MakeDeterministicTestIdentities(int(as.n))
				require.NoError(t, err)
				tapes := make([]transcripts.Transcript, as.n)
				for i := range tapes {
					tapes[i] = hagrid.NewTranscript("test", nil)
				}

				seeds := runSeedSetup(t, as.th, identities, tapes, prng)
				lhs := make([]*riss.IntShare, as.n)
				rhs := make([]*riss.IntShare, as.n)
				for i := range as.n {
					lhs[i], err = seeds[i].Sample(riss.WithModulus(modulus))
					require.NoError(t, err)
					rhs[i], err = seeds[i].Sample(riss.WithModulus(modulus))
					require.NoError(t, err)
				}

				dealer, err := riss.NewDealer(as.th, as.n, riss.WithModulus(modulus))
				require.NoError(t, err)
				l, err := dealer.Open(lhs...)
				require.NoError(t, err)
				r, err := dealer.Open(rhs...)
				require.NoError(t, err)
				expected := new(big.Int).Mul(l, r)
				expected.Mod(expected, modulus)

				productsShares := runMulPub(t, as.th, identities, tapes, seeds, prng, lhs, rhs, riss.WithModulus(modulus))
				product, err := dealer.Open(productsShares...)
				require.Zero(t, product.Cmp(expected))
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

func runMulPub(tb testing.TB, threshold uint, identities []types.IdentityKey, tapes []transcripts.Transcript, seeds []*riss.PseudoRandomSeed, prng io.Reader, lhs, rhs []*riss.IntShare, opts ...riss.SharingOpt) []*riss.IntShare {
	tb.Helper()

	protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, int(threshold))
	require.NoError(tb, err)

	participants := make([]*rissMul.Participant, len(identities))
	for i := range participants {
		participants[i], err = rissMul.NewParticipant(identities[i], protocol, tapes[i], prng, seeds[i], opts...)
		require.NoError(tb, err)
	}

	r1Out := make([]network.RoundMessages[types.ThresholdProtocol, *rissMul.Round1P2P], len(participants))
	for i, party := range participants {
		r1Out[i], err = party.Round1(lhs[i], rhs[i])
		require.NoError(tb, err)
	}

	r2In := testutils.MapUnicastO2I(tb, participants, r1Out)
	results := make([]*riss.IntShare, len(participants))
	for i, party := range participants {
		results[i], err = party.Round2(r2In[i])
		require.NoError(tb, err)
	}

	return results
}
