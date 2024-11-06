package prob_prime_two_three_test

import (
	crand "crypto/rand"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/prob_prime_two_three"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"
	"io"
	"math/big"
	"testing"
)

func Test_Primes(t *testing.T) {
	t.Parallel()
	const primeBitLen = 512
	prng := crand.Reader

	for range 128 {
		p, q := samplePrimes(t, primeBitLen, prng)
		n := new(big.Int).Mul(p, q)
		isProbablyPrime := runDistributedProbablyPrime(t, p, q, n, primeBitLen, prng)
		require.True(t, isProbablyPrime)
	}
}

func Test_NonPrimes(t *testing.T) {
	t.Parallel()
	const primeBitLen = 512
	prng := crand.Reader

	for range 128 {
		p, q := sampleNonPrimeAndPrime(t, primeBitLen, prng)
		n := new(big.Int).Mul(p, q)
		isProbablyPrime := runDistributedProbablyPrime(t, p, q, n, primeBitLen, prng)
		require.False(t, isProbablyPrime)
	}
}

func runDistributedProbablyPrime(tb testing.TB, p, q, n *big.Int, primeBitLen uint, prng io.Reader) bool {
	identities, err := testutils.MakeDeterministicTestIdentities(3)
	require.NoError(tb, err)

	protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, 2)
	require.NoError(tb, err)

	dealer, err := replicated.NewIntDealer(2, 3, replicated.BitLen(primeBitLen), replicated.SpecialForm(true))
	require.NoError(tb, err)
	pShares, err := dealer.Share(p, prng)
	require.NoError(tb, err)
	qShares, err := dealer.Share(q, prng)
	require.NoError(tb, err)
	require.NotNil(tb, qShares)
	var sessionId [128 / 8]byte
	_, err = io.ReadFull(prng, sessionId[:])
	require.NoError(tb, err)

	tapes := make([]transcripts.Transcript, 3)
	participants := make([]*prob_prime_two_three.Participant, 3)
	for i := range participants {
		tapes[i] = hagrid.NewTranscript("TEST", nil)
		tapes[i].AppendMessages("sessionId", sessionId[:])
		participants[i] = prob_prime_two_three.NewParticipant(tapes[i], identities[i], protocol, n, prng)
	}

	r1Out := make([]network.RoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round1P2P], 3)
	gammas := make([]*big.Int, len(participants))
	for i, participant := range participants {
		r1Out[i], gammas[i] = participant.Round1(pShares[participant.SharingId()], qShares[participant.SharingId()])
	}
	r2In := testutils.MapUnicastO2I(tb, participants, r1Out)

	r2Out := make([]network.RoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round2P2P], 3)
	for i, participant := range participants {
		r2Out[i] = participant.Round2(r2In[i])
	}
	r3In := testutils.MapUnicastO2I(tb, participants, r2Out)

	r3Out := make([]network.RoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round3P2P], 3)
	for i, participant := range participants {
		r3Out[i] = participant.Round3(r3In[i])
	}
	r4In := testutils.MapUnicastO2I(tb, participants, r3Out)

	r4Out := make([]network.RoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round4P2P], 3)
	for i, participant := range participants {
		r4Out[i] = participant.Round4(r4In[i])
	}
	r5In := testutils.MapUnicastO2I(tb, participants, r4Out)

	r5Out := make([]network.RoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round5P2P], 3)
	for i, participant := range participants {
		r5Out[i] = participant.Round5(r5In[i])
	}
	r6In := testutils.MapUnicastO2I(tb, participants, r5Out)

	r6Out := make([]network.RoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round6P2P], 3)
	for i, participant := range participants {
		r6Out[i] = participant.Round6(r6In[i])
	}
	r7In := testutils.MapUnicastO2I(tb, participants, r6Out)

	r7Out := make([]network.RoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round7P2P], 3)
	for i, participant := range participants {
		r7Out[i] = participant.Round7(r7In[i])
	}
	r8In := testutils.MapUnicastO2I(tb, participants, r7Out)

	r8Out := make([]network.RoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round8P2P], 3)
	for i, participant := range participants {
		r8Out[i] = participant.Round8(r8In[i])
	}
	r9In := testutils.MapUnicastO2I(tb, participants, r8Out)

	r9Out := make([]network.RoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round9P2P], 3)
	for i, participant := range participants {
		r9Out[i] = participant.Round9(r9In[i])
	}
	r10In := testutils.MapUnicastO2I(tb, participants, r9Out)

	r10Out := make([]network.RoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round10P2P], 3)
	for i, participant := range participants {
		r10Out[i] = participant.Round10(r10In[i])
	}
	r11In := testutils.MapUnicastO2I(tb, participants, r10Out)

	r11Out := make([]*prob_prime_two_three.Round11Broadcast, 3)
	for i, participant := range participants {
		r11Out[i] = participant.Round11(r11In[i])
	}
	r12In := testutils.MapBroadcastO2I(tb, participants, r11Out)

	probablyPrimes := make([]bool, 3)
	for i, participant := range participants {
		probablyPrimes[i] = participant.Round12(r12In[i])
	}

	require.Equal(tb, probablyPrimes[0], probablyPrimes[1])
	require.Equal(tb, probablyPrimes[0], probablyPrimes[2])

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
