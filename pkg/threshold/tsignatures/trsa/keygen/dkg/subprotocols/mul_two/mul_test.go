package mul_two_test

import (
	crand "crypto/rand"
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/mul_two"
	"github.com/stretchr/testify/require"
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
	bound := new(big.Int)
	bound.SetBit(bound, bitLen, 1)

	for _, as := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", as.t, as.n), func(t *testing.T) {
			t.Parallel()

			lhsSecret, err := crand.Int(prng, bound)
			require.NoError(t, err)
			rhsSecret, err := crand.Int(prng, bound)
			require.NoError(t, err)
			product := new(big.Int).Mul(lhsSecret, rhsSecret)

			dealer, err := replicated.NewIntDealer(as.t, as.n, replicated.BitLen(bitLen))
			require.NoError(t, err)
			lhsShares, err := dealer.Share(lhsSecret, prng)
			require.NoError(t, err)
			rhsShares, err := dealer.Share(rhsSecret, prng)

			identities, err := testutils.MakeDeterministicTestIdentities(int(as.n))
			require.NoError(t, err)

			protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, int(as.t))
			require.NoError(t, err)

			participants := make([]*mul_two.Participant, len(identities))
			for i, identity := range identities {
				participants[i] = mul_two.NewParticipant(identity, protocol, prng, replicated.BitLen(2*bitLen))
			}

			r1Out := make([]network.RoundMessages[types.ThresholdProtocol, *mul_two.Round1P2P], len(participants))
			for i, participant := range participants {
				r1Out[i] = participant.Round1(lhsShares[participant.MySharingId], rhsShares[participant.MySharingId])
			}
			r2In := testutils.MapUnicastO2I(t, participants, r1Out)

			results := make([]*replicated.IntShare, len(participants))
			for i, participant := range participants {
				results[i] = participant.Round2(r2In[i])
			}

			result, err := dealer.Reveal(results...)
			require.NoError(t, err)
			require.Zero(t, result.Cmp(product))
		})
	}
}

func Test_HappyPathMod(t *testing.T) {
	t.Parallel()

	const bitLen = 512
	prng := crand.Reader
	bound := new(big.Int)
	bound.SetBit(bound, bitLen, 1)

	for _, as := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", as.t, as.n), func(t *testing.T) {
			t.Parallel()

			modulus, err := crand.Int(prng, bound)
			require.NoError(t, err)

			lhsSecret, err := crand.Int(prng, modulus)
			require.NoError(t, err)
			rhsSecret, err := crand.Int(prng, modulus)
			require.NoError(t, err)

			product := new(big.Int).Mul(lhsSecret, rhsSecret)
			product.Mod(product, modulus)

			dealer, err := replicated.NewIntDealer(as.t, as.n, replicated.Modulus(modulus))
			require.NoError(t, err)
			lhsShares, err := dealer.Share(lhsSecret, prng)
			require.NoError(t, err)
			rhsShares, err := dealer.Share(rhsSecret, prng)

			identities, err := testutils.MakeDeterministicTestIdentities(int(as.n))
			require.NoError(t, err)

			protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, int(as.t))
			require.NoError(t, err)

			participants := make([]*mul_two.Participant, len(identities))
			for i, identity := range identities {
				participants[i] = mul_two.NewParticipant(identity, protocol, prng, replicated.Modulus(modulus))
			}

			r1Out := make([]network.RoundMessages[types.ThresholdProtocol, *mul_two.Round1P2P], len(participants))
			for i, participant := range participants {
				r1Out[i] = participant.Round1(lhsShares[participant.MySharingId], rhsShares[participant.MySharingId])
			}
			r2In := testutils.MapUnicastO2I(t, participants, r1Out)

			results := make([]*replicated.IntShare, len(participants))
			for i, participant := range participants {
				results[i] = participant.Round2(r2In[i])
			}

			result, err := dealer.Reveal(results...)
			require.NoError(t, err)
			require.Zero(t, result.Cmp(product))
		})
	}
}
