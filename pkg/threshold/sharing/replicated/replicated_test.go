package replicated_test

import (
	crand "crypto/rand"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/combinatorics"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
)

var accessStructures = []struct{ th, n uint }{
	{th: 2, n: 3},
	{th: 2, n: 5},
	{th: 6, n: 10},
	{th: 10, n: 11},
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	const bitLen = 2048
	prng := crand.Reader

	for _, as := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", as.th, as.n), func(t *testing.T) {
			t.Parallel()

			bound := new(big.Int)
			bound.SetBit(bound, bitLen, 1)
			secret, err := crand.Int(prng, bound)
			require.NoError(t, err)

			dealer, err := replicated.NewIntDealer(as.th, as.n, replicated.BitLen(bitLen))
			require.NoError(t, err)
			shares, err := dealer.Share(secret, prng)
			require.NoError(t, err)

			for sharingId, share := range shares {
				require.Equal(t, sharingId, share.SharingId())

				testThreshold, testTotal := share.ThresholdAccessStructure()
				require.Equal(t, as.th, testThreshold)
				require.Equal(t, as.n, testTotal)
			}

			for shareCount := as.th; shareCount <= as.n; shareCount++ {
				combinations, err := combinatorics.Combinations(slices.Collect(maps.Values(shares)), shareCount)
				require.NoError(t, err)

				for _, combination := range combinations {
					revealed, err := dealer.Reveal(combination...)
					require.NoError(t, err)
					require.True(t, revealed.Cmp(secret) == 0)
				}
			}

			for shareCount := 0; shareCount < int(as.th); shareCount++ {
				combinations, err := combinatorics.Combinations(slices.Collect(maps.Values(shares)), uint(shareCount))
				require.NoError(t, err)

				for _, combination := range combinations {
					_, err := dealer.Reveal(combination...)
					require.Error(t, err)
				}
			}
		})
	}
}

func Test_HappyPathMod(t *testing.T) {
	t.Parallel()

	const bitLen = 2048
	prng := crand.Reader

	for _, as := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", as.th, as.n), func(t *testing.T) {
			t.Parallel()

			bound := new(big.Int)
			bound.SetBit(bound, bitLen, 1)
			modulus, err := crand.Int(prng, bound)
			require.NoError(t, err)
			secret, err := crand.Int(prng, modulus)
			require.NoError(t, err)

			dealer, err := replicated.NewIntDealer(as.th, as.n, replicated.Modulus(modulus))
			require.NoError(t, err)
			shares, err := dealer.Share(secret, prng)
			require.NoError(t, err)

			for sharingId, share := range shares {
				require.Equal(t, sharingId, share.SharingId())

				testThreshold, testTotal := share.ThresholdAccessStructure()
				require.Equal(t, as.th, testThreshold)
				require.Equal(t, as.n, testTotal)
			}

			for shareCount := as.th; shareCount <= as.n; shareCount++ {
				combinations, err := combinatorics.Combinations(slices.Collect(maps.Values(shares)), shareCount)
				require.NoError(t, err)

				for _, combination := range combinations {
					revealed, err := dealer.Reveal(combination...)
					require.NoError(t, err)
					require.True(t, revealed.Cmp(secret) == 0)
				}
			}

			for shareCount := 0; shareCount < int(as.th); shareCount++ {
				combinations, err := combinatorics.Combinations(slices.Collect(maps.Values(shares)), uint(shareCount))
				require.NoError(t, err)

				for _, combination := range combinations {
					_, err := dealer.Reveal(combination...)
					require.Error(t, err)
				}
			}
		})
	}
}

func Test_HappyPathSpecial3Mod4(t *testing.T) {
	t.Parallel()

	const bitLen = 2048
	prng := crand.Reader

	for _, as := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", as.th, as.n), func(t *testing.T) {
			t.Parallel()

			bound := new(big.Int)
			bound.SetBit(bound, bitLen, 1)
			secret, err := crand.Int(prng, bound)
			require.NoError(t, err)
			secret.SetBit(secret, 0, 1)
			secret.SetBit(secret, 1, 1)

			dealer, err := replicated.NewIntDealer(as.th, as.n, replicated.BitLen(bitLen), replicated.SpecialForm(true))
			require.NoError(t, err)
			shares, err := dealer.Share(secret, prng)
			require.NoError(t, err)

			smallestSharingIdSet := replicated.SharingIdSet((uint64(1) << (as.th - 1)) - 1)
			for sharingId, share := range shares {
				require.Equal(t, sharingId, share.SharingId())

				testThreshold, testTotal := share.ThresholdAccessStructure()
				require.Equal(t, as.th, testThreshold)
				require.Equal(t, as.n, testTotal)

				for sharingIdSet, subShareValue := range share.SubShares {
					if sharingIdSet == smallestSharingIdSet {
						require.Equal(t, uint(1), subShareValue.Bit(0))
						require.Equal(t, uint(1), subShareValue.Bit(0))
					} else {
						require.Equal(t, uint(0), subShareValue.Bit(0))
						require.Equal(t, uint(0), subShareValue.Bit(0))
					}
				}
			}

			for shareCount := as.th; shareCount <= as.n; shareCount++ {
				combinations, err := combinatorics.Combinations(slices.Collect(maps.Values(shares)), shareCount)
				require.NoError(t, err)

				for _, combination := range combinations {
					revealed, err := dealer.Reveal(combination...)
					require.NoError(t, err)
					require.True(t, revealed.Cmp(secret) == 0)
				}
			}

			for shareCount := 0; shareCount < int(as.th); shareCount++ {
				combinations, err := combinatorics.Combinations(slices.Collect(maps.Values(shares)), uint(shareCount))
				require.NoError(t, err)

				for _, combination := range combinations {
					_, err := dealer.Reveal(combination...)
					require.Error(t, err)
				}
			}
		})
	}
}

func Test_HappyPathSpecial0Mod4(t *testing.T) {
	t.Parallel()

	const bitLen = 2048
	prng := crand.Reader

	for _, as := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", as.th, as.n), func(t *testing.T) {
			t.Parallel()

			bound := new(big.Int)
			bound.SetBit(bound, bitLen, 1)
			secret, err := crand.Int(prng, bound)
			require.NoError(t, err)
			secret.SetBit(secret, 0, 0)
			secret.SetBit(secret, 1, 0)

			dealer, err := replicated.NewIntDealer(as.th, as.n, replicated.BitLen(bitLen), replicated.SpecialForm(true))
			require.NoError(t, err)
			shares, err := dealer.Share(secret, prng)
			require.NoError(t, err)

			for sharingId, share := range shares {
				require.Equal(t, sharingId, share.SharingId())

				testThreshold, testTotal := share.ThresholdAccessStructure()
				require.Equal(t, as.th, testThreshold)
				require.Equal(t, as.n, testTotal)

				for _, subShareValue := range share.SubShares {
					require.Equal(t, uint(0), subShareValue.Bit(0))
					require.Equal(t, uint(0), subShareValue.Bit(0))
				}
			}

			for shareCount := as.th; shareCount <= as.n; shareCount++ {
				combinations, err := combinatorics.Combinations(slices.Collect(maps.Values(shares)), shareCount)
				require.NoError(t, err)

				for _, combination := range combinations {
					revealed, err := dealer.Reveal(combination...)
					require.NoError(t, err)
					require.True(t, revealed.Cmp(secret) == 0)
				}
			}

			for shareCount := 0; shareCount < int(as.th); shareCount++ {
				combinations, err := combinatorics.Combinations(slices.Collect(maps.Values(shares)), uint(shareCount))
				require.NoError(t, err)

				for _, combination := range combinations {
					_, err := dealer.Reveal(combination...)
					require.Error(t, err)
				}
			}
		})
	}
}

func Test_LinearAdd(t *testing.T) {
	t.Parallel()

	const bitLen = 2048
	prng := crand.Reader

	for _, as := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", as.th, as.n), func(t *testing.T) {
			t.Parallel()

			bound := new(big.Int)
			bound.SetBit(bound, bitLen, 1)
			secret1, err := crand.Int(prng, bound)
			require.NoError(t, err)
			secret2, err := crand.Int(prng, bound)
			require.NoError(t, err)
			secret := new(big.Int).Add(secret1, secret2)

			dealer, err := replicated.NewIntDealer(as.th, as.n, replicated.BitLen(bitLen))
			require.NoError(t, err)
			shares1, err := dealer.Share(secret1, prng)
			require.NoError(t, err)
			shares2, err := dealer.Share(secret2, prng)
			require.NoError(t, err)
			shares := make(map[types.SharingID]*replicated.IntShare)
			for k, v := range shares1 {
				shares[k] = v.Add(shares2[k])
			}

			for shareCount := as.th; shareCount <= as.n; shareCount++ {
				combinations, err := combinatorics.Combinations(slices.Collect(maps.Values(shares)), shareCount)
				require.NoError(t, err)

				for _, combination := range combinations {
					revealed, err := dealer.Reveal(combination...)
					require.NoError(t, err)
					require.True(t, revealed.Cmp(secret) == 0)
				}
			}

			for shareCount := 0; shareCount < int(as.th); shareCount++ {
				combinations, err := combinatorics.Combinations(slices.Collect(maps.Values(shares)), uint(shareCount))
				require.NoError(t, err)

				for _, combination := range combinations {
					_, err := dealer.Reveal(combination...)
					require.Error(t, err)
				}
			}
		})
	}
}

func Test_LinearAddValue(t *testing.T) {
	t.Parallel()

	const bitLen = 2048
	prng := crand.Reader

	for _, as := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", as.th, as.n), func(t *testing.T) {
			t.Parallel()

			bound := new(big.Int)
			bound.SetBit(bound, bitLen, 1)
			secret1, err := crand.Int(prng, bound)
			require.NoError(t, err)
			secret2, err := crand.Int(prng, bound)
			require.NoError(t, err)
			secret := new(big.Int).Add(secret1, secret2)

			dealer, err := replicated.NewIntDealer(as.th, as.n, replicated.BitLen(bitLen))
			require.NoError(t, err)
			shares1, err := dealer.Share(secret1, prng)
			require.NoError(t, err)
			shares := make(map[types.SharingID]*replicated.IntShare)
			for k, v := range shares1 {
				shares[k] = v.AddValue(secret2)
			}

			for shareCount := as.th; shareCount <= as.n; shareCount++ {
				combinations, err := combinatorics.Combinations(slices.Collect(maps.Values(shares)), shareCount)
				require.NoError(t, err)

				for _, combination := range combinations {
					revealed, err := dealer.Reveal(combination...)
					require.NoError(t, err)
					require.True(t, revealed.Cmp(secret) == 0)
				}
			}

			for shareCount := 0; shareCount < int(as.th); shareCount++ {
				combinations, err := combinatorics.Combinations(slices.Collect(maps.Values(shares)), uint(shareCount))
				require.NoError(t, err)

				for _, combination := range combinations {
					_, err := dealer.Reveal(combination...)
					require.Error(t, err)
				}
			}
		})
	}
}

func Test_LinearSub(t *testing.T) {
	t.Parallel()

	const bitLen = 2048
	prng := crand.Reader

	for _, as := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", as.th, as.n), func(t *testing.T) {
			t.Parallel()

			bound := new(big.Int)
			bound.SetBit(bound, bitLen, 1)
			secret1, err := crand.Int(prng, bound)
			require.NoError(t, err)
			secret2, err := crand.Int(prng, bound)
			require.NoError(t, err)
			secret := new(big.Int).Sub(secret1, secret2)

			dealer, err := replicated.NewIntDealer(as.th, as.n, replicated.BitLen(bitLen))
			require.NoError(t, err)
			shares1, err := dealer.Share(secret1, prng)
			require.NoError(t, err)
			shares2, err := dealer.Share(secret2, prng)
			require.NoError(t, err)
			shares := make(map[types.SharingID]*replicated.IntShare)
			for k, v := range shares1 {
				shares[k] = v.Sub(shares2[k])
			}

			for shareCount := as.th; shareCount <= as.n; shareCount++ {
				combinations, err := combinatorics.Combinations(slices.Collect(maps.Values(shares)), shareCount)
				require.NoError(t, err)

				for _, combination := range combinations {
					revealed, err := dealer.Reveal(combination...)
					require.NoError(t, err)
					require.True(t, revealed.Cmp(secret) == 0)
				}
			}

			for shareCount := 0; shareCount < int(as.th); shareCount++ {
				combinations, err := combinatorics.Combinations(slices.Collect(maps.Values(shares)), uint(shareCount))
				require.NoError(t, err)

				for _, combination := range combinations {
					_, err := dealer.Reveal(combination...)
					require.Error(t, err)
				}
			}
		})
	}
}

func Test_LinearSubValue(t *testing.T) {
	t.Parallel()

	const bitLen = 2048
	prng := crand.Reader

	for _, as := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", as.th, as.n), func(t *testing.T) {
			t.Parallel()

			bound := new(big.Int)
			bound.SetBit(bound, bitLen, 1)
			secret1, err := crand.Int(prng, bound)
			require.NoError(t, err)
			secret2, err := crand.Int(prng, bound)
			require.NoError(t, err)
			secret := new(big.Int).Sub(secret1, secret2)

			dealer, err := replicated.NewIntDealer(as.th, as.n, replicated.BitLen(bitLen))
			require.NoError(t, err)
			shares1, err := dealer.Share(secret1, prng)
			require.NoError(t, err)
			shares := make(map[types.SharingID]*replicated.IntShare)
			for k, v := range shares1 {
				shares[k] = v.SubValue(secret2)
			}

			for shareCount := as.th; shareCount <= as.n; shareCount++ {
				combinations, err := combinatorics.Combinations(slices.Collect(maps.Values(shares)), shareCount)
				require.NoError(t, err)

				for _, combination := range combinations {
					revealed, err := dealer.Reveal(combination...)
					require.NoError(t, err)
					require.True(t, revealed.Cmp(secret) == 0)
				}
			}

			for shareCount := 0; shareCount < int(as.th); shareCount++ {
				combinations, err := combinatorics.Combinations(slices.Collect(maps.Values(shares)), uint(shareCount))
				require.NoError(t, err)

				for _, combination := range combinations {
					_, err := dealer.Reveal(combination...)
					require.Error(t, err)
				}
			}
		})
	}
}

func Test_LinearNeg(t *testing.T) {
	t.Parallel()

	const bitLen = 2048
	prng := crand.Reader

	for _, as := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", as.th, as.n), func(t *testing.T) {
			t.Parallel()

			bound := new(big.Int)
			bound.SetBit(bound, bitLen, 1)
			secret1, err := crand.Int(prng, bound)
			require.NoError(t, err)
			secret := new(big.Int).Neg(secret1)

			dealer, err := replicated.NewIntDealer(as.th, as.n, replicated.BitLen(bitLen))
			require.NoError(t, err)
			shares1, err := dealer.Share(secret1, prng)
			require.NoError(t, err)
			shares := make(map[types.SharingID]*replicated.IntShare)
			for k, v := range shares1 {
				shares[k] = v.Neg()
			}

			for shareCount := as.th; shareCount <= as.n; shareCount++ {
				combinations, err := combinatorics.Combinations(slices.Collect(maps.Values(shares)), shareCount)
				require.NoError(t, err)

				for _, combination := range combinations {
					revealed, err := dealer.Reveal(combination...)
					require.NoError(t, err)
					require.True(t, revealed.Cmp(secret) == 0)
				}
			}

			for shareCount := 0; shareCount < int(as.th); shareCount++ {
				combinations, err := combinatorics.Combinations(slices.Collect(maps.Values(shares)), uint(shareCount))
				require.NoError(t, err)

				for _, combination := range combinations {
					_, err := dealer.Reveal(combination...)
					require.Error(t, err)
				}
			}
		})
	}
}

func Test_LinearMulValue(t *testing.T) {
	t.Parallel()

	const bitLen = 2048
	prng := crand.Reader

	for _, as := range accessStructures {
		t.Run(fmt.Sprintf("(%d,%d)", as.th, as.n), func(t *testing.T) {
			t.Parallel()

			bound := new(big.Int)
			bound.SetBit(bound, bitLen, 1)
			secret1, err := crand.Int(prng, bound)
			require.NoError(t, err)
			secret2, err := crand.Int(prng, bound)
			require.NoError(t, err)
			secret := new(big.Int).Mul(secret1, secret2)

			dealer, err := replicated.NewIntDealer(as.th, as.n, replicated.BitLen(bitLen))
			require.NoError(t, err)
			shares1, err := dealer.Share(secret1, prng)
			require.NoError(t, err)
			shares := make(map[types.SharingID]*replicated.IntShare)
			for k, v := range shares1 {
				shares[k] = v.MulValue(secret2)
			}

			for shareCount := as.th; shareCount <= as.n; shareCount++ {
				combinations, err := combinatorics.Combinations(slices.Collect(maps.Values(shares)), shareCount)
				require.NoError(t, err)

				for _, combination := range combinations {
					revealed, err := dealer.Reveal(combination...)
					require.NoError(t, err)
					require.True(t, revealed.Cmp(secret) == 0)
				}
			}

			for shareCount := 0; shareCount < int(as.th); shareCount++ {
				combinations, err := combinatorics.Combinations(slices.Collect(maps.Values(shares)), uint(shareCount))
				require.NoError(t, err)

				for _, combination := range combinations {
					_, err := dealer.Reveal(combination...)
					require.Error(t, err)
				}
			}
		})
	}
}
