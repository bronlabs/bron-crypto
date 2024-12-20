package riss_mul_pub_test

import (
	crand "crypto/rand"
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/riss"
	rissMulPub "github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/riss/protocols/mul_pub"
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
	{th: 3, n: 6, iters: 32},
	{th: 4, n: 7, iters: 16},
	{th: 4, n: 8, iters: 16},
	{th: 5, n: 9, iters: 8},
	{th: 5, n: 10, iters: 4},
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	const bitLen = 2048
	prng := crand.Reader

	for _, ac := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", ac.th, ac.n), func(t *testing.T) {
			t.Parallel()

			for range ac.iters {
				identities, err := testutils.MakeDeterministicTestIdentities(int(ac.n))
				require.NoError(t, err)
				tapes := make([]transcripts.Transcript, ac.n)
				for i := range tapes {
					tapes[i] = hagrid.NewTranscript("test", nil)
				}

				seeds := runSeedSetup(t, ac.th, identities, tapes, prng)
				lhs := make([]*riss.IntShare, ac.n)
				rhs := make([]*riss.IntShare, ac.n)
				for i := range ac.n {
					lhs[i], err = seeds[i].Sample(riss.WithBitLen(bitLen))
					require.NoError(t, err)
					rhs[i], err = seeds[i].Sample(riss.WithBitLen(bitLen))
					require.NoError(t, err)
				}

				dealer, err := riss.NewDealer(ac.th, ac.n, riss.WithBitLen(bitLen))
				require.NoError(t, err)
				l, err := dealer.Open(lhs...)
				require.NoError(t, err)
				r, err := dealer.Open(rhs...)
				require.NoError(t, err)
				expected := new(big.Int).Mul(l, r)
				products := runMulPub(t, ac.th, identities, tapes, seeds, prng, lhs, rhs, riss.WithBitLen(2*bitLen))
				for _, p := range products {
					require.Zero(t, p.Cmp(expected))
				}
			}
		})
	}
}

func Test_HappyPathMod(t *testing.T) {
	t.Parallel()
	prng := crand.Reader
	modulusBound := new(big.Int)
	modulusBound.SetBit(modulusBound, 2048, 1)
	modulus, err := crand.Int(prng, modulusBound)
	require.NoError(t, err)

	for _, ac := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", ac.th, ac.n), func(t *testing.T) {
			t.Parallel()

			for range ac.iters {
				identities, err := testutils.MakeDeterministicTestIdentities(int(ac.n))
				require.NoError(t, err)
				tapes := make([]transcripts.Transcript, ac.n)
				for i := range tapes {
					tapes[i] = hagrid.NewTranscript("test", nil)
				}

				seeds := runSeedSetup(t, ac.th, identities, tapes, prng)
				lhs := make([]*riss.IntShare, ac.n)
				rhs := make([]*riss.IntShare, ac.n)
				for i := range ac.n {
					lhs[i], err = seeds[i].Sample(riss.WithModulus(modulus))
					require.NoError(t, err)
					rhs[i], err = seeds[i].Sample(riss.WithModulus(modulus))
					require.NoError(t, err)
				}

				dealer, err := riss.NewDealer(ac.th, ac.n, riss.WithModulus(modulus))
				require.NoError(t, err)
				l, err := dealer.Open(lhs...)
				require.NoError(t, err)
				r, err := dealer.Open(rhs...)
				require.NoError(t, err)
				expected := new(big.Int).Mul(l, r)
				expected.Mod(expected, modulus)
				products := runMulPub(t, ac.th, identities, tapes, seeds, prng, lhs, rhs, riss.WithModulus(modulus))
				for _, p := range products {
					require.Zero(t, p.Cmp(expected))
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

func runMulPub(tb testing.TB, threshold uint, identities []types.IdentityKey, tapes []transcripts.Transcript, seeds []*riss.PseudoRandomSeed, prng io.Reader, lhs, rhs []*riss.IntShare, opts ...riss.SharingOpt) []*big.Int {
	tb.Helper()

	protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, int(threshold))
	require.NoError(tb, err)

	participants := make([]*rissMulPub.Participant, len(identities))
	for i := range participants {
		participants[i], err = rissMulPub.NewParticipant(identities[i], protocol, tapes[i], prng, seeds[i], opts...)
		require.NoError(tb, err)
	}

	r1Out := make([]network.RoundMessages[types.ThresholdProtocol, *rissMulPub.Round1P2P], len(participants))
	for i, party := range participants {
		r1Out[i], err = party.Round1(lhs[i], rhs[i])
		require.NoError(tb, err)
	}

	r2In := testutils.MapUnicastO2I(tb, participants, r1Out)
	results := make([]*big.Int, len(participants))
	for i, party := range participants {
		results[i], err = party.Round2(r2In[i])
		require.NoError(tb, err)
	}

	return results
}
