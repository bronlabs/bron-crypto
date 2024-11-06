package prob_prime_test

import (
	crand "crypto/rand"
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/prob_prime"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slices"
	"io"
	"math/big"
	"testing"
)

var accessStructures = []struct{ t, n uint }{
	{t: 2, n: 3},
	{t: 3, n: 5},
}

func Test_Primes(t *testing.T) {
	t.Parallel()
	const primeBitLen = 2048
	prng := crand.Reader

	for _, as := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", as.t, as.n), func(t *testing.T) {
			t.Parallel()

			for range 16 {
				p, q := samplePrimes(t, primeBitLen, prng)
				n := new(big.Int).Mul(p, q)
				isProbablyPrime := runDistributedProbablyPrime(t, as.t, as.n, p, q, n, primeBitLen, prng)
				require.True(t, isProbablyPrime)
			}
		})
	}
}

func Test_NonPrimes(t *testing.T) {
	t.Parallel()
	const primeBitLen = 2048
	prng := crand.Reader

	for _, as := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", as.t, as.n), func(t *testing.T) {
			t.Parallel()

			for range 16 {
				p, q := sampleNonPrimeAndPrime(t, primeBitLen, prng)
				n := new(big.Int).Mul(p, q)
				isProbablyPrime := runDistributedProbablyPrime(t, as.t, as.n, p, q, n, primeBitLen, prng)
				require.False(t, isProbablyPrime)
			}
		})
	}
}

func runDistributedProbablyPrime(tb testing.TB, threshold, total uint, p, q, n *big.Int, primeBitLen uint, prng io.Reader) bool {
	identities, err := testutils.MakeDeterministicTestIdentities(int(total))
	require.NoError(tb, err)

	protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, int(threshold))
	require.NoError(tb, err)

	dealer, err := replicated.NewIntDealer(threshold, total, replicated.BitLen(primeBitLen), replicated.SpecialForm(true))
	require.NoError(tb, err)
	pShares, err := dealer.Share(p, prng)
	require.NoError(tb, err)
	qShares, err := dealer.Share(q, prng)
	require.NoError(tb, err)
	require.NotNil(tb, qShares)
	var sessionId [128 / 8]byte
	_, err = io.ReadFull(prng, sessionId[:])
	require.NoError(tb, err)

	tapes := make([]transcripts.Transcript, len(identities))
	participants := make([]*prob_prime.Participant, len(identities))
	for i := range participants {
		tapes[i] = hagrid.NewTranscript("TEST", nil)
		tapes[i].AppendMessages("sessionId", sessionId[:])
		participants[i] = prob_prime.NewParticipant(tapes[i], identities[i], protocol, n, prng)
	}

	r1Out := make([]network.RoundMessages[types.ThresholdProtocol, *prob_prime.Round1P2P], len(participants))
	gammas := make([]*big.Int, len(participants))
	for i, participant := range participants {
		r1Out[i], gammas[i] = participant.Round1(pShares[participant.SharingId()], qShares[participant.SharingId()])
	}

	r2Out := make([]network.RoundMessages[types.ThresholdProtocol, *prob_prime.Round2P2P], len(participants))
	r2In := testutils.MapUnicastO2I(tb, participants, r1Out)
	for i, participant := range participants {
		r2Out[i] = participant.Round2(r2In[i])
	}

	r3Out := make([]network.RoundMessages[types.ThresholdProtocol, *prob_prime.Round3P2P], len(participants))
	for slices.Contains(r3Out, nil) {
		r3In := testutils.MapUnicastO2I(tb, participants, r2Out)
		for i, participant := range participants {
			r2Out[i], r3Out[i] = participant.Round3R(r3In[i])
		}
	}

	r4Out := make([]network.RoundMessages[types.ThresholdProtocol, *prob_prime.Round4P2P], len(participants))
	for slices.Contains(r4Out, nil) {
		r4In := testutils.MapUnicastO2I(tb, participants, r3Out)
		for i, participant := range participants {
			r3Out[i], r4Out[i] = participant.Round4R(r4In[i])
		}
	}

	r5Out := make([]network.RoundMessages[types.ThresholdProtocol, *prob_prime.Round5P2P], len(participants))
	for slices.Contains(r5Out, nil) {
		r5In := testutils.MapUnicastO2I(tb, participants, r4Out)
		for i, participant := range participants {
			r4Out[i], r5Out[i] = participant.Round5R(r5In[i])
		}
	}

	r6Out := make([]*prob_prime.Round6Broadcast, len(participants))
	for slices.Contains(r6Out, nil) {
		r6In := testutils.MapUnicastO2I(tb, participants, r5Out)
		for i, participant := range participants {
			r5Out[i], r6Out[i] = participant.Round6R(r6In[i])
		}
	}

	probablyPrimes := make([]bool, len(participants))
	r7In := testutils.MapBroadcastO2I(tb, participants, r6Out)
	for i, participant := range participants {
		probablyPrimes[i] = participant.Round7(r7In[i])
		if i > 0 {
			require.Equal(tb, probablyPrimes[i-1], probablyPrimes[i])
		}
	}

	return probablyPrimes[0]
}

func samplePrimes(tb testing.TB, bitLen uint, prng io.Reader) (p, q *big.Int) {
	var err error
	for {
		p, err = crand.Prime(prng, int(bitLen))
		require.NoError(tb, err)
		if p.Bit(int(bitLen)-1) == 1 && p.Bit(int(bitLen)-2) == 1 && p.Bit(1) == 1 {
			break
		}
	}
	for {
		q, err = crand.Prime(prng, int(bitLen))
		require.NoError(tb, err)
		if q.Bit(int(bitLen)-1) == 1 && q.Bit(int(bitLen)-2) == 1 && q.Bit(1) == 1 {
			break
		}
	}

	return p, q
}

func sampleNonPrimeAndPrime(tb testing.TB, bitLen uint, prng io.Reader) (*big.Int, *big.Int) {
	var err error
	var p, q *big.Int
	pBound := new(big.Int)
	pBound.SetBit(pBound, int(bitLen), 1)
	for {
		p, err = crand.Int(prng, pBound)
		require.NoError(tb, err)
		p.SetBit(p, int(bitLen)-1, 1)
		p.SetBit(p, int(bitLen)-2, 1)
		p.SetBit(p, 1, 1)
		p.SetBit(p, 0, 1)

		if !p.ProbablyPrime(2) {
			break
		}
	}
	for {
		q, err = crand.Prime(prng, int(bitLen))
		require.NoError(tb, err)
		if q.Bit(int(bitLen)-1) == 1 && q.Bit(int(bitLen)-2) == 1 && q.Bit(1) == 1 {
			break
		}
	}

	return p, q
}
