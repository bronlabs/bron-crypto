package intshamir_test

import (
	crand "crypto/rand"
	"io"
	"maps"
	"slices"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/combinatorics"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/intshamir"
)

const bitLen = 4096

var supportedAccessStructures = []struct{ t, n uint }{
	{2, 3},
	{2, 5},
	{5, 10},
	{11, 12},
}

func Test_IntHappyPath(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	for _, as := range supportedAccessStructures {
		scheme, err := intshamir.NewIntScheme(as.t, as.n)
		require.NoError(t, err)

		secret := randomInt(t, prng)
		shares, err := scheme.Deal(secret, prng)
		require.NoError(t, err)
		shareValues := slices.Collect(maps.Values(shares))

		for s := as.t; s <= as.n; s++ {
			combinations, err := combinatorics.Combinations(shareValues, s)
			require.NoError(t, err)

			for _, sharesSubset := range combinations {
				reconstructed, err := scheme.Open(sharesSubset...)
				require.NoError(t, err)
				require.True(t, reconstructed.Eq(secret) != 0)
			}
		}
	}
}

func Test_IntLinearAdd(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	for _, as := range supportedAccessStructures {
		scheme, err := intshamir.NewIntScheme(as.t, as.n)
		require.NoError(t, err)

		secretX := randomInt(t, prng)
		sharesX, err := scheme.Deal(secretX, prng)
		require.NoError(t, err)

		secretY := randomInt(t, prng)
		sharesY, err := scheme.Deal(secretY, prng)
		require.NoError(t, err)

		secret := new(saferith.Int).Add(secretX, secretY, -1)
		shares := make(map[types.SharingID]*intshamir.IntShare)
		for id, x := range sharesX {
			shares[id] = x.Add(sharesY[id])
		}
		shareValues := slices.Collect(maps.Values(shares))

		for s := as.t; s <= as.n; s++ {
			combinations, err := combinatorics.Combinations(shareValues, s)
			require.NoError(t, err)

			for _, sharesSubset := range combinations {
				reconstructed, err := scheme.Open(sharesSubset...)
				require.NoError(t, err)
				require.True(t, reconstructed.Eq(secret) != 0)
			}
		}
	}
}

func Test_IntLinearAddValue(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	for _, as := range supportedAccessStructures {
		scheme, err := intshamir.NewIntScheme(as.t, as.n)
		require.NoError(t, err)

		secretX := randomInt(t, prng)
		sharesX, err := scheme.Deal(secretX, prng)
		require.NoError(t, err)

		secretY := randomInt(t, prng)

		secret := new(saferith.Int).Add(secretX, secretY, -1)
		shares := make(map[types.SharingID]*intshamir.IntShare)
		for id, x := range sharesX {
			shares[id] = x.AddValue(secretY)
		}
		shareValues := slices.Collect(maps.Values(shares))

		for s := as.t; s <= as.n; s++ {
			combinations, err := combinatorics.Combinations(shareValues, s)
			require.NoError(t, err)

			for _, sharesSubset := range combinations {
				reconstructed, err := scheme.Open(sharesSubset...)
				require.NoError(t, err)
				require.True(t, reconstructed.Eq(secret) != 0)
			}
		}
	}
}

func Test_IntLinearSub(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	for _, as := range supportedAccessStructures {
		scheme, err := intshamir.NewIntScheme(as.t, as.n)
		require.NoError(t, err)

		secretX := randomInt(t, prng)
		sharesX, err := scheme.Deal(secretX, prng)
		require.NoError(t, err)

		secretY := randomInt(t, prng)
		sharesY, err := scheme.Deal(secretY, prng)
		require.NoError(t, err)

		secret := new(saferith.Int).Add(secretX, secretY.Clone().Neg(1), -1)
		shares := make(map[types.SharingID]*intshamir.IntShare)
		for id, x := range sharesX {
			shares[id] = x.Sub(sharesY[id])
		}
		shareValues := slices.Collect(maps.Values(shares))

		for s := as.t; s <= as.n; s++ {
			combinations, err := combinatorics.Combinations(shareValues, s)
			require.NoError(t, err)

			for _, sharesSubset := range combinations {
				reconstructed, err := scheme.Open(sharesSubset...)
				require.NoError(t, err)
				require.True(t, reconstructed.Eq(secret) != 0)
			}
		}
	}
}

func Test_IntLinearSubValue(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	for _, as := range supportedAccessStructures {
		scheme, err := intshamir.NewIntScheme(as.t, as.n)
		require.NoError(t, err)

		secretX := randomInt(t, prng)
		sharesX, err := scheme.Deal(secretX, prng)
		require.NoError(t, err)

		secretY := randomInt(t, prng)

		secret := new(saferith.Int).Add(secretX, secretY.Clone().Neg(1), -1)
		shares := make(map[types.SharingID]*intshamir.IntShare)
		for id, x := range sharesX {
			shares[id] = x.SubValue(secretY)
		}
		shareValues := slices.Collect(maps.Values(shares))

		for s := as.t; s <= as.n; s++ {
			combinations, err := combinatorics.Combinations(shareValues, s)
			require.NoError(t, err)

			for _, sharesSubset := range combinations {
				reconstructed, err := scheme.Open(sharesSubset...)
				require.NoError(t, err)
				require.True(t, reconstructed.Eq(secret) != 0)
			}
		}
	}
}

func Test_IntLinearMulScalar(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	for _, as := range supportedAccessStructures {
		scheme, err := intshamir.NewIntScheme(as.t, as.n)
		require.NoError(t, err)

		secretX := randomInt(t, prng)
		sharesX, err := scheme.Deal(secretX, prng)
		require.NoError(t, err)

		secretY := randomInt(t, prng)

		secret := new(saferith.Int).Mul(secretX, secretY, -1)
		shares := make(map[types.SharingID]*intshamir.IntShare)
		for id, x := range sharesX {
			shares[id] = x.MulScalar(secretY)
		}
		shareValues := slices.Collect(maps.Values(shares))

		for s := as.t; s <= as.n; s++ {
			combinations, err := combinatorics.Combinations(shareValues, s)
			require.NoError(t, err)

			for _, sharesSubset := range combinations {
				reconstructed, err := scheme.Open(sharesSubset...)
				require.NoError(t, err)
				require.True(t, reconstructed.Eq(secret) != 0)
			}
		}
	}
}

func randomInt(tb testing.TB, prng io.Reader) *saferith.Int {
	tb.Helper()

	byteLen := (bitLen+7)/8 + 1
	iData := make([]byte, byteLen)
	_, err := io.ReadFull(prng, iData)
	require.NoError(tb, err)
	i := new(saferith.Int)
	err = i.UnmarshalBinary(iData)
	require.NoError(tb, err)
	return i
}
