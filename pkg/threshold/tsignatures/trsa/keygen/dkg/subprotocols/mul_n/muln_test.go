package mul_n_test

import (
	crand "crypto/rand"
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/mul_n"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

var accessStructures = []struct{ t, n uint }{
	{t: 2, n: 3},
	{t: 2, n: 5},
	{t: 3, n: 6},
}

var numsCases = []int{2, 6, 18, 31, 32, 33}

func Test_HappyPathSpecialMultiple(t *testing.T) {
	t.Parallel()

	const bitLen = 4096
	prng := crand.Reader
	bound := new(big.Int)
	bound.SetBit(bound, bitLen, 1)

	for _, nums := range numsCases {
		for _, as := range accessStructures {
			t.Run(fmt.Sprintf("(%d,%d):%d", as.t, as.n, nums), func(t *testing.T) {
				t.Parallel()

				xs := make([]*big.Int, nums)
				y := new(big.Int).SetInt64(1)
				for i := range xs {
					var err error
					xs[i], err = crand.Int(prng, bound)
					require.NoError(t, err)
					y.Mul(y, xs[i])
				}

				dealer, err := replicated.NewIntDealer(as.t, as.n, replicated.BitLen(bitLen))
				require.NoError(t, err)
				xShares := make([]map[types.SharingID]*replicated.IntShare, nums)
				for i, x := range xs {
					var err error
					xShares[i], err = dealer.Share(x, prng)
					require.NoError(t, err)
				}

				identities, err := testutils.MakeDeterministicTestIdentities(int(as.n))
				require.NoError(t, err)

				protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, int(as.t))
				require.NoError(t, err)

				participants := make([]*mul_n.Participant, len(identities))
				for i, identity := range identities {
					participants[i] = mul_n.NewParticipant(identity, protocol, prng, replicated.BitLen(bitLen), replicated.SpecialForm(true))
				}

				r1Out := make([]network.RoundMessages[types.ThresholdProtocol, *mul_n.Round1P2P], len(participants))
				for i, participant := range participants {
					shares := make([]*replicated.IntShare, nums)
					for j, share := range xShares {
						shares[j] = share[participant.SharingId()]
					}

					r1Out[i] = participant.Round1(shares...)
				}
				r2In := testutils.MapUnicastO2I(t, participants, r1Out)

				results := make([]*replicated.IntShare, len(participants))
				for results[0] == nil {
					for i, participant := range participants {
						r2In[i], results[i] = participant.Round2R(r2In[i])
					}
					r2In = testutils.MapUnicastO2I(t, participants, r2In)
				}

				result, err := dealer.Reveal(results...)
				require.NoError(t, err)
				require.Zero(t, result.Cmp(y))

				minSet := replicated.SharingIdSet((1 << (as.t - 1)) - 1)
				for _, resultShare := range results {
					for set, subShareVal := range resultShare.SubShares {
						if set != minSet {
							require.Equal(t, uint(0), subShareVal.Bit(0))
							require.Equal(t, uint(0), subShareVal.Bit(1))
						}
					}
				}
			})
		}
	}
}

func Test_HappyPathModMultiple(t *testing.T) {
	t.Parallel()

	const bitLen = 512
	prng := crand.Reader
	bound := new(big.Int)
	bound.SetBit(bound, bitLen, 1)

	for _, nums := range numsCases {
		for _, as := range accessStructures {
			t.Run(fmt.Sprintf("(%d,%d):%d", as.t, as.n, nums), func(t *testing.T) {
				t.Parallel()

				modulus, err := crand.Int(prng, bound)
				require.NoError(t, err)

				xs := make([]*big.Int, nums)
				y := new(big.Int).SetInt64(1)
				for i := range xs {
					var err error
					xs[i], err = crand.Int(prng, bound)
					require.NoError(t, err)
					y.Mul(y, xs[i])
					y.Mod(y, modulus)
				}

				dealer, err := replicated.NewIntDealer(as.t, as.n, replicated.Modulus(modulus))
				require.NoError(t, err)
				xShares := make([]map[types.SharingID]*replicated.IntShare, nums)
				for i, x := range xs {
					var err error
					xShares[i], err = dealer.Share(x, prng)
					require.NoError(t, err)
				}
				for _, xShare := range xShares {
					for _, share := range xShare {
						for _, subShare := range share.SubShares {
							require.Negative(t, subShare.Cmp(modulus))
						}
					}
				}

				identities, err := testutils.MakeDeterministicTestIdentities(int(as.n))
				require.NoError(t, err)

				protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, int(as.t))
				require.NoError(t, err)

				participants := make([]*mul_n.Participant, len(identities))
				for i, identity := range identities {
					participants[i] = mul_n.NewParticipant(identity, protocol, prng, replicated.Modulus(modulus))
				}

				r1Out := make([]network.RoundMessages[types.ThresholdProtocol, *mul_n.Round1P2P], len(participants))
				for i, participant := range participants {
					shares := make([]*replicated.IntShare, nums)
					for j, share := range xShares {
						shares[j] = share[participant.SharingId()]
					}

					r1Out[i] = participant.Round1(shares...)
				}
				r2In := testutils.MapUnicastO2I(t, participants, r1Out)

				results := make([]*replicated.IntShare, len(participants))
				for results[0] == nil {
					for i, participant := range participants {
						r2In[i], results[i] = participant.Round2R(r2In[i])
					}
					r2In = testutils.MapUnicastO2I(t, participants, r2In)
				}
				for _, result := range results {
					for _, subShare := range result.SubShares {
						require.Negative(t, subShare.Cmp(modulus))
					}
				}

				result, err := dealer.Reveal(results...)
				require.NoError(t, err)
				require.Zero(t, result.Cmp(y))
			})
		}
	}
}

func Test_HappyPathMultiple(t *testing.T) {
	t.Parallel()

	const bitLen = 512
	prng := crand.Reader
	bound := new(big.Int)
	bound.SetBit(bound, bitLen, 1)

	for _, nums := range numsCases {
		for _, as := range accessStructures {
			t.Run(fmt.Sprintf("(%d,%d):%d", as.t, as.n, nums), func(t *testing.T) {
				t.Parallel()

				xs := make([]*big.Int, nums)
				y := new(big.Int).SetInt64(1)
				for i := range xs {
					var err error
					xs[i], err = crand.Int(prng, bound)
					require.NoError(t, err)
					y.Mul(y, xs[i])
				}

				dealer, err := replicated.NewIntDealer(as.t, as.n, replicated.BitLen(bitLen))
				require.NoError(t, err)
				xShares := make([]map[types.SharingID]*replicated.IntShare, nums)
				for i, x := range xs {
					var err error
					xShares[i], err = dealer.Share(x, prng)
					require.NoError(t, err)
				}

				identities, err := testutils.MakeDeterministicTestIdentities(int(as.n))
				require.NoError(t, err)

				protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, int(as.t))
				require.NoError(t, err)

				participants := make([]*mul_n.Participant, len(identities))
				for i, identity := range identities {
					participants[i] = mul_n.NewParticipant(identity, protocol, prng, replicated.BitLen(bitLen))
				}

				r1Out := make([]network.RoundMessages[types.ThresholdProtocol, *mul_n.Round1P2P], len(participants))
				for i, participant := range participants {
					shares := make([]*replicated.IntShare, nums)
					for j, share := range xShares {
						shares[j] = share[participant.SharingId()]
					}

					r1Out[i] = participant.Round1(shares...)
				}
				r2In := testutils.MapUnicastO2I(t, participants, r1Out)

				results := make([]*replicated.IntShare, len(participants))
				for results[0] == nil {
					for i, participant := range participants {
						r2In[i], results[i] = participant.Round2R(r2In[i])
					}
					r2In = testutils.MapUnicastO2I(t, participants, r2In)
				}

				result, err := dealer.Reveal(results...)
				require.NoError(t, err)
				require.Zero(t, result.Cmp(y))
			})
		}
	}
}
