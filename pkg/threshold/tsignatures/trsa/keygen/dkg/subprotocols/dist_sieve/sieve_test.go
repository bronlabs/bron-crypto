package dist_sieve_test

import (
	crand "crypto/rand"
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/dist_sieve"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/sieve"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"
	"io"
	"math/big"
	"slices"
	"testing"
)

var accessStructures = []struct{ t, n uint }{
	{t: 2, n: 3},
	{t: 2, n: 4},
	{t: 3, n: 5},
}

func Test_HappyPath2048(t *testing.T) {
	t.Parallel()
	const primeBitLen = 2048
	const reps = 128
	prng := crand.Reader
	mb, ok := new(big.Int).SetString("140c0978a984a35bd9e457e0eb42a176254cfacb4a08b83062e48cc4e1ae5518c7c5ba388cd2944a3eab794bcfb06990e551a21cbd523749b99c2cde2d637c1df7404b7e6c5e5250946db6a2ceb8fa4bd58ea3324aac18f438e08e12717be5031da85a084a62617de1b25cb2d089c0e77ba817a2ade867e137bfa7c70ed3490b9e527016f38313139da1cdd887798f6e610fc3f729d19e5a68eb8eec0b8e0fed663ee42f898c51b45c64c7c61507820cc26f1e82a6794fae2ba9c570f81c285748c5cdff6a0dc13f2f0a18e7c967ef44995317b40b818d58cccdb55a029a5fe7ee271f4d1bbabd3e1d25db954c56ac906", 16)
	require.True(t, ok)

	for _, as := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", as.t, as.n), func(t *testing.T) {
			t.Parallel()

			c := 0
			for range reps {
				pShares := runDistributedSieve(t, primeBitLen, as.t, as.n, prng)
				qShares := runDistributedSieve(t, primeBitLen, as.t, as.n, prng)

				dealer, err := replicated.NewIntDealer(as.t, as.n, replicated.BitLen(primeBitLen), replicated.SpecialForm(true))
				require.NoError(t, err)

				p, err := dealer.Reveal(pShares...)
				require.NoError(t, err)
				q, err := dealer.Reveal(qShares...)
				require.NoError(t, err)

				require.Equal(t, primeBitLen, p.BitLen())
				require.Equal(t, uint(1), p.Bit(1))
				require.Equal(t, uint(1), p.Bit(0))

				require.Equal(t, primeBitLen, q.BitLen())
				require.Equal(t, uint(1), q.Bit(1))
				require.Equal(t, uint(1), q.Bit(0))

				gcdP := new(big.Int).GCD(nil, nil, p, mb)
				require.Zero(t, gcdP.Cmp(big.NewInt(1)))
				gcdQ := new(big.Int).GCD(nil, nil, q, mb)
				require.Zero(t, gcdQ.Cmp(big.NewInt(1)))

				n := new(big.Int).Mul(p, q)
				require.Equal(t, primeBitLen*2, n.BitLen())

				gcdN := new(big.Int).GCD(nil, nil, n, sieve.ParamMB)
				if gcdN.Cmp(big.NewInt(1)) == 0 {
					c++
				}
			}
			rate := 100 * float32(c) / reps
			fmt.Printf("%g%%\n\n", rate)
		})
	}
}

func runDistributedSieve(tb testing.TB, primeBitLen, threshold, total uint, prng io.Reader) (pShares []*replicated.IntShare) {
	identities, err := testutils.MakeDeterministicTestIdentities(int(total))
	require.NoError(tb, err)
	protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, int(threshold))
	require.NoError(tb, err)
	var sessionId [128 / 8]byte
	_, err = io.ReadFull(prng, sessionId[:])
	require.NoError(tb, err)

	participants := make([]*dist_sieve.Participant, total)
	for i := range participants {
		tape := hagrid.NewTranscript("TEST", nil)
		tape.AppendMessages("sessionId", sessionId[:])
		participants[i] = dist_sieve.NewParticipant(tape, identities[i], protocol, primeBitLen, prng)
	}

	r1Out := make([]network.RoundMessages[types.ThresholdProtocol, *dist_sieve.Round1P2P], len(participants))
	for i, participant := range participants {
		r1Out[i] = participant.Round1()
	}

	r2Out := make([]network.RoundMessages[types.ThresholdProtocol, *dist_sieve.Round2P2P], len(participants))
	r2In := testutils.MapUnicastO2I(tb, participants, r1Out)
	for i, participant := range participants {
		r2Out[i] = participant.Round2(r2In[i])
	}

	r3Out := make([]*dist_sieve.Round3Broadcast, len(participants))
	for slices.Contains(r3Out, nil) {
		r3In := testutils.MapUnicastO2I(tb, participants, r2Out)
		for i, participant := range participants {
			r2Out[i], r3Out[i] = participant.Round3R(r3In[i])
		}
	}

	r4Out := make([]*dist_sieve.Round4Broadcast, len(participants))
	r4In := testutils.MapBroadcastO2I(tb, participants, r3Out)
	for i, participant := range participants {
		r4Out[i] = participant.Round4(r4In[i])
	}

	pShares = make([]*replicated.IntShare, len(participants))
	r5In := testutils.MapBroadcastO2I(tb, participants, r4Out)
	for i, participant := range participants {
		pShares[i] = participant.Round5(r5In[i])
	}

	for _, pShare := range pShares {
		for set, setValue := range pShare.SubShares {
			if set == replicated.SharingIdSet((1<<(threshold-1))-1) {
				require.Equal(tb, uint(1), setValue.Bit(0))
				require.Equal(tb, uint(1), setValue.Bit(1))
			} else {
				require.Equal(tb, uint(0), setValue.Bit(0))
				require.Equal(tb, uint(0), setValue.Bit(1))
			}
		}
	}

	return pShares
}
