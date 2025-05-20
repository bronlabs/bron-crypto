package rep23_test

import (
	crand "crypto/rand"
	"crypto/rsa"
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

const rsaLen = 4096
const intLen = 1024 // small enough to not overflow

func Test_HappyPathExp(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	base, modulus := randBaseMod(t, prng)

	secret := randSmallInt(t, prng)
	secretInExp := new(saferith.Nat).ExpI(base, secret, modulus)

	dealer := rep23.NewIntExpScheme(modulus)
	shares, err := dealer.Deal(secretInExp, prng)
	require.NoError(t, err)
	require.Len(t, shares, total)

	shareValues := slices.Collect(maps.Values(shares))
	reconstructed, err := dealer.Open(shareValues...)
	require.NoError(t, err)
	require.Equal(t, saferith.Choice(1), reconstructed.Eq(secretInExp))

	combinations, err := combinatorics.Combinations(shareValues, threshold)
	require.NoError(t, err)
	for _, combination := range combinations {
		reconstructed, err := dealer.Open(combination...)
		require.NoError(t, err)
		require.Equal(t, saferith.Choice(1), reconstructed.Eq(secretInExp))
	}
}

func Test_LinearAddExp(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	base, modulus := randBaseMod(t, prng)

	dealer := rep23.NewIntExpScheme(modulus)
	secretA := randSmallInt(t, prng)
	secretAInExp := new(saferith.Nat).ExpI(base, secretA, modulus)
	secretB := randSmallInt(t, prng)
	secretBInExp := new(saferith.Nat).ExpI(base, secretB, modulus)

	sharesA, err := dealer.Deal(secretAInExp, prng)
	require.NoError(t, err)
	require.NotNil(t, sharesA)

	sharesB, err := dealer.Deal(secretBInExp, prng)
	require.NoError(t, err)
	require.NotNil(t, sharesB)

	secret := new(saferith.Int).Add(secretA, secretB, -1)
	secretInExp := new(saferith.Nat).ExpI(base, secret, modulus)
	shares := sharing.AddSharesMap(dealer, sharesA, sharesB)

	recomputedSecret, err := dealer.Open(slices.Collect(maps.Values(shares))...)
	require.NoError(t, err)
	require.NotNil(t, recomputedSecret)
	require.Equal(t, saferith.Choice(1), secretInExp.Eq(recomputedSecret))
}

func Test_LinearAddValueExp(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	base, modulus := randBaseMod(t, prng)

	dealer := rep23.NewIntExpScheme(modulus)
	secretA := randSmallInt(t, prng)
	secretAInExp := new(saferith.Nat).ExpI(base, secretA, modulus)
	secretB := randSmallInt(t, prng)
	secretBInExp := new(saferith.Nat).ExpI(base, secretB, modulus)

	sharesA, err := dealer.Deal(secretAInExp, prng)
	require.NoError(t, err)
	require.NotNil(t, sharesA)

	secret := new(saferith.Int).Add(secretA, secretB, -1)
	secretInExp := new(saferith.Nat).ExpI(base, secret, modulus)
	shares := sharing.AddSharesValueMap(dealer, sharesA, secretBInExp)

	recomputedSecret, err := dealer.Open(slices.Collect(maps.Values(shares))...)
	require.NoError(t, err)
	require.NotNil(t, recomputedSecret)
	require.Equal(t, saferith.Choice(1), secretInExp.Eq(recomputedSecret))
}

func Test_LinearSubExp(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	base, modulus := randBaseMod(t, prng)

	dealer := rep23.NewIntExpScheme(modulus)
	secretA := randSmallInt(t, prng)
	secretAInExp := new(saferith.Nat).ExpI(base, secretA, modulus)
	secretB := randSmallInt(t, prng)
	secretBInExp := new(saferith.Nat).ExpI(base, secretB, modulus)

	sharesA, err := dealer.Deal(secretAInExp, prng)
	require.NoError(t, err)
	require.NotNil(t, sharesA)

	sharesB, err := dealer.Deal(secretBInExp, prng)
	require.NoError(t, err)
	require.NotNil(t, sharesB)

	secret := new(saferith.Int).Add(secretA, secretB.Clone().Neg(1), -1)
	secretInExp := new(saferith.Nat).ExpI(base, secret, modulus)
	shares := sharing.SubSharesMap(dealer, sharesA, sharesB)

	recomputedSecret, err := dealer.Open(slices.Collect(maps.Values(shares))...)
	require.NoError(t, err)
	require.NotNil(t, recomputedSecret)
	require.Equal(t, saferith.Choice(1), secretInExp.Eq(recomputedSecret))
}

func Test_LinearSubValueExp(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	base, modulus := randBaseMod(t, prng)

	dealer := rep23.NewIntExpScheme(modulus)
	secretA := randSmallInt(t, prng)
	secretAInExp := new(saferith.Nat).ExpI(base, secretA, modulus)
	secretB := randSmallInt(t, prng)
	secretBInExp := new(saferith.Nat).ExpI(base, secretB, modulus)

	sharesA, err := dealer.Deal(secretAInExp, prng)
	require.NoError(t, err)
	require.NotNil(t, sharesA)

	secret := new(saferith.Int).Add(secretA, secretB.Clone().Neg(1), -1)
	secretInExp := new(saferith.Nat).ExpI(base, secret, modulus)
	shares := sharing.SubSharesValueMap(dealer, sharesA, secretBInExp)

	recomputedSecret, err := dealer.Open(slices.Collect(maps.Values(shares))...)
	require.NoError(t, err)
	require.NotNil(t, recomputedSecret)
	require.Equal(t, saferith.Choice(1), secretInExp.Eq(recomputedSecret))
}

func Test_LinearNegExp(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	base, modulus := randBaseMod(t, prng)

	dealer := rep23.NewIntExpScheme(modulus)
	secretA := randSmallInt(t, prng)
	secretAInExp := new(saferith.Nat).ExpI(base, secretA, modulus)

	sharesA, err := dealer.Deal(secretAInExp, prng)
	require.NoError(t, err)
	require.NotNil(t, sharesA)

	secret := secretA.Clone().Neg(1)
	secretInExp := new(saferith.Nat).ExpI(base, secret, modulus)
	shares := sharing.NegSharesMap(dealer, sharesA)

	recomputedSecret, err := dealer.Open(slices.Collect(maps.Values(shares))...)
	require.NoError(t, err)
	require.NotNil(t, recomputedSecret)
	require.Equal(t, saferith.Choice(1), secretInExp.Eq(recomputedSecret))
}

func Test_LinearScalarMulExp(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	base, modulus := randBaseMod(t, prng)

	dealer := rep23.NewIntExpScheme(modulus)
	secretA := randSmallInt(t, prng)
	secretAInExp := new(saferith.Nat).ExpI(base, secretA, modulus)
	secretB := randSmallInt(t, prng)

	sharesA, err := dealer.Deal(secretAInExp, prng)
	require.NoError(t, err)
	require.NotNil(t, sharesA)

	secret := new(saferith.Int).Mul(secretA, secretB, -1)
	secretInExp := new(saferith.Nat).ExpI(base, secret, modulus)
	shares := sharing.MulSharesMap(dealer, sharesA, secretB)

	recomputedSecret, err := dealer.Open(slices.Collect(maps.Values(shares))...)
	require.NoError(t, err)
	require.NotNil(t, recomputedSecret)
	require.Equal(t, saferith.Choice(1), secretInExp.Eq(recomputedSecret))
}

func randBaseMod(tb testing.TB, prng io.Reader) (*saferith.Nat, *saferith.Modulus) {
	tb.Helper()

	sk, err := rsa.GenerateKey(prng, rsaLen)
	require.NoError(tb, err)
	base, err := crand.Int(prng, sk.N)
	require.NoError(tb, err)

	return new(saferith.Nat).SetBig(base, sk.N.BitLen()), saferith.ModulusFromBytes(sk.N.Bytes())
}

func randSmallInt(tb testing.TB, prng io.Reader) *saferith.Int {
	tb.Helper()

	var data [(intLen+7)/8 + 1]byte
	_, err := io.ReadFull(prng, data[:])
	require.NoError(tb, err)
	result := new(saferith.Int)
	err = result.UnmarshalBinary(data[:])
	require.NoError(tb, err)
	return result
}
