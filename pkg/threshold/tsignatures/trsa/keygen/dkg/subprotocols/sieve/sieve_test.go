package sieve_test

import (
	crand "crypto/rand"
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/sieve"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"
	"io"
	"math/big"
	"testing"
)

var accessStructures = []struct{ t, n uint }{
	{t: 2, n: 3},
	{t: 2, n: 5},
	{t: 3, n: 6},
}

func Test_HappyPath2048(t *testing.T) {
	t.Parallel()
	const primeBitLen = 2048
	prng := crand.Reader

	for _, as := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", as.t, as.n), func(t *testing.T) {
			t.Parallel()

			pShares, qShares, n := runDistributedSieve(t, primeBitLen, as.t, as.n, prng)
			dealer, err := replicated.NewIntDealer(as.t, as.n, replicated.BitLen(primeBitLen))
			require.NoError(t, err)

			p, err := dealer.Reveal(pShares...)
			require.NoError(t, err)
			q, err := dealer.Reveal(qShares...)
			require.NoError(t, err)

			require.True(t, new(big.Int).Mul(p, q).Cmp(n) == 0)
			require.Equal(t, primeBitLen, p.BitLen())
			require.Equal(t, primeBitLen, q.BitLen())
			require.Equal(t, 2*primeBitLen, n.BitLen())

			require.Equal(t, uint(1), p.Bit(0))
			require.Equal(t, uint(1), p.Bit(1))
			require.Equal(t, uint(1), q.Bit(0))
			require.Equal(t, uint(1), q.Bit(1))

			pGcd := new(big.Int).GCD(nil, nil, sieve.ParamMB, p)
			qGcd := new(big.Int).GCD(nil, nil, sieve.ParamMB, p)
			require.Zero(t, pGcd.Cmp(big.NewInt(1)))
			require.Zero(t, qGcd.Cmp(big.NewInt(1)))
		})
	}
}

func Test_HappyPath512(t *testing.T) {
	t.Parallel()
	const primeBitLen = 512
	prng := crand.Reader

	for _, as := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", as.t, as.n), func(t *testing.T) {
			t.Parallel()

			pShares, qShares, n := runDistributedSieve(t, primeBitLen, as.t, as.n, prng)
			dealer, err := replicated.NewIntDealer(as.t, as.n, replicated.BitLen(primeBitLen))
			require.NoError(t, err)

			p, err := dealer.Reveal(pShares...)
			require.NoError(t, err)
			q, err := dealer.Reveal(qShares...)
			require.NoError(t, err)

			require.True(t, new(big.Int).Mul(p, q).Cmp(n) == 0)
			require.Equal(t, primeBitLen, p.BitLen())
			require.Equal(t, primeBitLen, q.BitLen())
			require.Equal(t, 2*primeBitLen, n.BitLen())

			require.Equal(t, uint(1), p.Bit(0))
			require.Equal(t, uint(1), p.Bit(1))
			require.Equal(t, uint(1), q.Bit(0))
			require.Equal(t, uint(1), q.Bit(1))

			pGcd := new(big.Int).GCD(nil, nil, sieve.ParamMB, p)
			qGcd := new(big.Int).GCD(nil, nil, sieve.ParamMB, p)
			require.Zero(t, pGcd.Cmp(big.NewInt(1)))
			require.Zero(t, qGcd.Cmp(big.NewInt(1)))
		})
	}
}

func runDistributedSieve(tb testing.TB, primeBitLen, threshold, total uint, prng io.Reader) (pShares, qShares []*replicated.IntShare, n *big.Int) {
	identities, err := testutils.MakeDeterministicTestIdentities(int(total))
	require.NoError(tb, err)
	protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, int(threshold))
	require.NoError(tb, err)
	var sessionId [128 / 8]byte
	_, err = io.ReadFull(prng, sessionId[:])
	require.NoError(tb, err)

	k := 0
mainLoop:
	for {
		k++
		participants := make([]*sieve.Participant, total)
		for i := range participants {
			tape := hagrid.NewTranscript("TEST", nil)
			tape.AppendMessages("sessionId", sessionId[:])
			participants[i] = sieve.NewParticipant(tape, identities[i], protocol, primeBitLen, prng)
		}

		r1Out := make([]network.RoundMessages[types.ThresholdProtocol, *sieve.Round1P2P], len(participants))
		for i, participant := range participants {
			r1Out[i] = participant.Round1()
		}
		r2In := testutils.MapUnicastO2I(tb, participants, r1Out)

		r2Out := make([]network.RoundMessages[types.ThresholdProtocol, *sieve.Round2P2P], len(participants))
		for i, participant := range participants {
			r2Out[i] = participant.Round2(r2In[i])
		}
		r3In := testutils.MapUnicastO2I(tb, participants, r2Out)

		r3Out := make([]*sieve.Round3Broadcast, len(participants))
		for i, participant := range participants {
			r3Out[i] = participant.Round3(r3In[i])
		}
		r4In := testutils.MapBroadcastO2I(tb, participants, r3Out)

		pShares = make([]*replicated.IntShare, len(participants))
		qShares = make([]*replicated.IntShare, len(participants))
		ns := make([]*big.Int, len(participants))
		for i, participant := range participants {
			var ok bool
			pShares[i], qShares[i], ns[i], ok = participant.Round4(r4In[i])
			if !ok {
				continue mainLoop
			}
		}

		for i := 1; i < len(participants); i++ {
			require.True(tb, ns[0].Cmp(ns[i]) == 0)
		}

		print(k)
		return pShares, qShares, ns[0]
	}
}
