package rep23_test

import (
	crand "crypto/rand"
	"io"
	"maps"
	"slices"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/combinatorics"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/rep23"
)

const threshold = 2
const total = 3
const bitLen = 256

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	secret := randInt(t, prng)
	dealer := rep23.NewIntScheme()
	shares, err := dealer.Deal(secret, prng)
	require.NoError(t, err)
	require.Len(t, shares, total)

	shareValues := slices.Collect(maps.Values(shares))
	reconstructed, err := dealer.Open(shareValues...)
	require.NoError(t, err)
	require.Equal(t, saferith.Choice(1), reconstructed.Eq(secret))

	combinations, err := combinatorics.Combinations(shareValues, threshold)
	require.NoError(t, err)
	for _, combination := range combinations {
		reconstructed, err := dealer.Open(combination...)
		require.NoError(t, err)
		require.Equal(t, saferith.Choice(1), reconstructed.Eq(secret))
	}
}

func Test_LinearAdd(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	dealer := rep23.NewIntScheme()
	secretA := randInt(t, prng)
	secretB := randInt(t, prng)

	sharesA, err := dealer.Deal(secretA, prng)
	require.NoError(t, err)
	require.NotNil(t, sharesA)

	sharesB, err := dealer.Deal(secretB, prng)
	require.NoError(t, err)
	require.NotNil(t, sharesB)

	secret := new(saferith.Int).Add(secretA, secretB, -1)
	shares := sharing.AddSharesMap(dealer, sharesA, sharesB)

	recomputedSecret, err := dealer.Open(slices.Collect(maps.Values(shares))...)
	require.NoError(t, err)
	require.NotNil(t, recomputedSecret)
	require.Equal(t, saferith.Choice(1), secret.Eq(recomputedSecret))
}

func Test_LinearAddValue(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	dealer := rep23.NewIntScheme()
	secretA := randInt(t, prng)
	secretB := randInt(t, prng)

	sharesA, err := dealer.Deal(secretA, prng)
	require.NoError(t, err)
	require.NotNil(t, sharesA)

	secret := new(saferith.Int).Add(secretA, secretB, -1)
	shares := sharing.AddSharesValueMap(dealer, sharesA, secretB)

	recomputedSecret, err := dealer.Open(slices.Collect(maps.Values(shares))...)
	require.NoError(t, err)
	require.NotNil(t, recomputedSecret)
	require.Equal(t, saferith.Choice(1), secret.Eq(recomputedSecret))
}

func Test_LinearSub(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	dealer := rep23.NewIntScheme()
	secretA := randInt(t, prng)
	secretB := randInt(t, prng)

	sharesA, err := dealer.Deal(secretA, prng)
	require.NoError(t, err)
	require.NotNil(t, sharesA)

	sharesB, err := dealer.Deal(secretB, prng)
	require.NoError(t, err)
	require.NotNil(t, sharesB)

	secret := new(saferith.Int).Add(secretA, secretB.Clone().Neg(1), -1)
	shares := sharing.SubSharesMap(dealer, sharesA, sharesB)

	recomputedSecret, err := dealer.Open(slices.Collect(maps.Values(shares))...)
	require.NoError(t, err)
	require.NotNil(t, recomputedSecret)
	require.Equal(t, saferith.Choice(1), secret.Eq(recomputedSecret))
}

func Test_LinearSubValue(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	dealer := rep23.NewIntScheme()
	secretA := randInt(t, prng)
	secretB := randInt(t, prng)

	sharesA, err := dealer.Deal(secretA, prng)
	require.NoError(t, err)
	require.NotNil(t, sharesA)

	secret := new(saferith.Int).Add(secretA, secretB.Clone().Neg(1), -1)
	shares := sharing.SubSharesValueMap(dealer, sharesA, secretB)

	recomputedSecret, err := dealer.Open(slices.Collect(maps.Values(shares))...)
	require.NoError(t, err)
	require.NotNil(t, recomputedSecret)
	require.Equal(t, saferith.Choice(1), secret.Eq(recomputedSecret))
}

func Test_LinearNeg(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	dealer := rep23.NewIntScheme()
	secretA := randInt(t, prng)

	sharesA, err := dealer.Deal(secretA, prng)
	require.NoError(t, err)
	require.NotNil(t, sharesA)

	secret := secretA.Clone().Neg(1)
	shares := sharing.NegSharesMap(dealer, sharesA)

	recomputedSecret, err := dealer.Open(slices.Collect(maps.Values(shares))...)
	require.NoError(t, err)
	require.NotNil(t, recomputedSecret)
	require.Equal(t, saferith.Choice(1), secret.Eq(recomputedSecret))
}

func Test_LinearScalarMul(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	dealer := rep23.NewIntScheme()
	secretA := randInt(t, prng)
	secretB := randInt(t, prng)

	sharesA, err := dealer.Deal(secretA, prng)
	require.NoError(t, err)
	require.NotNil(t, sharesA)

	secret := new(saferith.Int).Mul(secretA, secretB, -1)
	shares := sharing.MulSharesMap(dealer, sharesA, secretB)

	recomputedSecret, err := dealer.Open(slices.Collect(maps.Values(shares))...)
	require.NoError(t, err)
	require.NotNil(t, recomputedSecret)
	require.Equal(t, saferith.Choice(1), secret.Eq(recomputedSecret))
}

func randInt(tb testing.TB, prng io.Reader) *saferith.Int {
	tb.Helper()

	var data [(bitLen+7)/8 + 1]byte
	_, err := io.ReadFull(prng, data[:])
	require.NoError(tb, err)
	result := new(saferith.Int)
	err = result.UnmarshalBinary(data[:])
	require.NoError(tb, err)
	return result
}
