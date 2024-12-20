package riss_batch_mul_pub_test

import (
	crand "crypto/rand"
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

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	const threshold = 3
	const total = 5
	const bitLen = 2048
	const batch = 128
	prng := crand.Reader

	identities, err := testutils.MakeDeterministicTestIdentities(total)
	require.NoError(t, err)
	tapes := make([]transcripts.Transcript, total)
	for i := range tapes {
		tapes[i] = hagrid.NewTranscript("test", nil)
	}

	seeds := runSeedSetup(t, threshold, identities, tapes, prng)
	lhs := make([][]*riss.IntShare, total)
	rhs := make([][]*riss.IntShare, total)
	for i := range total {
		lhs[i] = make([]*riss.IntShare, batch)
		rhs[i] = make([]*riss.IntShare, batch)
		for k := range batch {
			lhs[i][k], err = seeds[i].Sample(riss.WithBitLen(bitLen))
			require.NoError(t, err)
			rhs[i][k], err = seeds[i].Sample(riss.WithBitLen(bitLen))
			require.NoError(t, err)
		}
	}

	dealer, err := riss.NewDealer(threshold, total, riss.WithBitLen(bitLen))
	require.NoError(t, err)
	expected := make([]*big.Int, batch)
	for k := range batch {
		var lShares []*riss.IntShare
		for i := range total {
			lShares = append(lShares, lhs[i][k])
		}
		var rShares []*riss.IntShare
		for i := range total {
			rShares = append(rShares, rhs[i][k])
		}
		l, err := dealer.Open(lShares...)
		require.NoError(t, err)
		r, err := dealer.Open(rShares...)
		require.NoError(t, err)
		expected[k] = new(big.Int).Mul(l, r)
	}

	products := runBatchMulPub(t, threshold, identities, tapes, seeds, prng, lhs, rhs, riss.WithBitLen(2*bitLen))
	for i := range total {
		for k := range batch {
			require.Zero(t, products[i][k].Cmp(expected[k]))
		}
	}
}

//func Test_HappyPathMod(t *testing.T) {
//	t.Parallel()
//	const threshold = 2
//	const total = 3
//	const iters = 128
//	prng := crand.Reader
//	modulusBound := new(big.Int)
//	modulusBound.SetBit(modulusBound, 2048, 1)
//	modulus, err := crand.Int(prng, modulusBound)
//	require.NoError(t, err)
//
//	for range iters {
//		identities, err := testutils.MakeDeterministicTestIdentities(total)
//		require.NoError(t, err)
//		tapes := make([]transcripts.Transcript, total)
//		for i := range tapes {
//			tapes[i] = hagrid.NewTranscript("test", nil)
//		}
//
//		seeds := runSeedSetup(t, threshold, identities, tapes, prng)
//		lhs := make([]*riss.IntShare, total)
//		rhs := make([]*riss.IntShare, total)
//		for i := range total {
//			lhs[i], err = seeds[i].Sample(riss.WithModulus(modulus))
//			require.NoError(t, err)
//			rhs[i], err = seeds[i].Sample(riss.WithModulus(modulus))
//			require.NoError(t, err)
//		}
//
//		dealer, err := riss.NewDealer(threshold, total, riss.WithModulus(modulus))
//		require.NoError(t, err)
//		l, err := dealer.Open(lhs...)
//		require.NoError(t, err)
//		r, err := dealer.Open(rhs...)
//		require.NoError(t, err)
//		expected := new(big.Int).Mul(l, r)
//		expected.Mod(expected, modulus)
//		products := runMulPub(t, threshold, identities, tapes, seeds, prng, lhs, rhs, riss.WithModulus(modulus))
//		for _, p := range products {
//			require.Zero(t, p.Cmp(expected))
//		}
//	}
//}

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
