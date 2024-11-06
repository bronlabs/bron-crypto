package inv_mod_test

import (
	crand "crypto/rand"
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/inv_mod"
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

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	const bitLen = 512
	prng := crand.Reader
	e := uint(65537)

	for _, as := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", as.t, as.n), func(t *testing.T) {
			t.Parallel()

			for range 1 {
				p, q := samplePrimes(t, bitLen, prng)
				pMinusOne := new(big.Int).Sub(p, big.NewInt(1))
				qMinusOne := new(big.Int).Sub(q, big.NewInt(1))
				phi := new(big.Int).Mul(pMinusOne, qMinusOne)

				eInv := runDistributedModInverse(t, e, phi, bitLen, as.t, as.n, prng)

				check := new(big.Int).Mul(eInv, big.NewInt(int64(e)))
				check.Mod(check, phi)
				require.Zero(t, check.Cmp(big.NewInt(1)))
			}
		})
	}
}

func runDistributedModInverse(tb testing.TB, e uint, phi *big.Int, primeLen uint, threshold, total uint, prng io.Reader) *big.Int {
	identities, err := testutils.MakeDeterministicTestIdentities(int(total))
	require.NoError(tb, err)
	protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, int(threshold))
	require.NoError(tb, err)
	dealer, err := replicated.NewIntDealer(threshold, total, replicated.BitLen(2*primeLen))
	require.NoError(tb, err)
	phiShares, err := dealer.Share(phi, prng)
	require.NoError(tb, err)
	var sessionId [128 / 8]byte
	_, err = io.ReadFull(prng, sessionId[:])
	require.NoError(tb, err)

	participants := make([]*inv_mod.Participant, total)
	for i := range participants {
		tape := hagrid.NewTranscript("TEST", nil)
		tape.AppendMessages("sessionId", sessionId[:])
		participants[i] = inv_mod.NewParticipant(tape, identities[i], protocol, primeLen, prng)
	}

again:
	for {
		r1Out := make([]network.RoundMessages[types.ThresholdProtocol, *inv_mod.Round1P2P], len(participants))
		for i, participant := range participants {
			r1Out[i] = participant.Round1()
		}
		r2In := testutils.MapUnicastO2I(tb, participants, r1Out)

		r2Out := make([]network.RoundMessages[types.ThresholdProtocol, *inv_mod.Round2P2P], len(participants))
		for i, participant := range participants {
			r2Out[i] = participant.Round2(e, phiShares[participant.SharingId()], r2In[i])
		}
		r3In := testutils.MapUnicastO2I(tb, participants, r2Out)

		r3Out := make([]*inv_mod.Round3Broadcast, len(participants))
		for i, participant := range participants {
			r3Out[i] = participant.Round3(r3In[i])
		}
		r4In := testutils.MapBroadcastO2I(tb, participants, r3Out)

		dShares := make([]*replicated.IntShare, len(participants))
		oks := make([]bool, len(participants))
		for i, participant := range participants {
			dShares[i], oks[i] = participant.Round4(r4In[i])
		}
		for _, ok := range oks {
			if !ok {
				continue again
			}
		}

		d, err := dealer.Reveal(dShares...)
		require.NoError(tb, err)
		return d
	}
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
