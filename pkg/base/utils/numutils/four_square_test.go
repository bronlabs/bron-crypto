package numutils_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/utils/numutils"
	saferith_utils "github.com/bronlabs/bron-crypto/pkg/base/utils/saferith"
)

func verify(mu *saferith.Nat, w1 *saferith.Nat, w2 *saferith.Nat, w3 *saferith.Nat, w4 *saferith.Nat) bool {
	w1Square := new(saferith.Nat).Mul(w1, w1, -1)
	w2Square := new(saferith.Nat).Mul(w2, w2, -1)
	w3Square := new(saferith.Nat).Mul(w3, w3, -1)
	w4Square := new(saferith.Nat).Mul(w4, w4, -1)
	firstSum := new(saferith.Nat).Add(w1Square, w2Square, -1)
	secondSum := new(saferith.Nat).Add(w3Square, w4Square, -1)
	return mu.Eq(new(saferith.Nat).Add(firstSum, secondSum, -1)) == 1
}

func Test_FourSquaresSmall(t *testing.T) {
	t.Parallel()
	for i := 0; i < 8193; i++ {
		mu := new(saferith.Nat).SetUint64(uint64(i))
		w1, w2, w3, w4, err := numutils.GetFourSquares(crand.Reader, mu)
		require.NoError(t, err)
		ok := verify(mu, w1, w2, w3, w4)
		require.True(t, ok)
	}
}

func Test_FourSquares32(t *testing.T) {
	t.Parallel()
	for i := 0; i < 1000; i++ {
		mu, err := saferith_utils.NatRandomBits(crand.Reader, 32)
		require.NoError(t, err)
		w1, w2, w3, w4, err := numutils.GetFourSquares(crand.Reader, mu)
		require.NoError(t, err)
		ok := verify(mu, w1, w2, w3, w4)
		require.True(t, ok)
	}
}

func Test_FourSquares64(t *testing.T) {
	t.Parallel()
	for i := 0; i < 1000; i++ {
		mu, err := saferith_utils.NatRandomBits(crand.Reader, 64)
		require.NoError(t, err)
		w1, w2, w3, w4, err := numutils.GetFourSquares(crand.Reader, mu)
		require.NoError(t, err)
		ok := verify(mu, w1, w2, w3, w4)
		require.True(t, ok)
	}
}

func Test_FourSquares128(t *testing.T) {
	t.Parallel()
	for i := 0; i < 100; i++ {
		mu, err := saferith_utils.NatRandomBits(crand.Reader, 128)
		require.NoError(t, err)
		w1, w2, w3, w4, err := numutils.GetFourSquares(crand.Reader, mu)
		require.NoError(t, err)
		ok := verify(mu, w1, w2, w3, w4)
		require.True(t, ok)
	}
}

func Test_FourSquares256(t *testing.T) {
	t.Parallel()
	for i := 0; i < 100; i++ {
		mu, err := saferith_utils.NatRandomBits(crand.Reader, 256)
		require.NoError(t, err)
		w1, w2, w3, w4, err := numutils.GetFourSquares(crand.Reader, mu)
		require.NoError(t, err)
		ok := verify(mu, w1, w2, w3, w4)
		require.True(t, ok)
	}
}

func Test_FourSquares512(t *testing.T) {
	t.Parallel()
	for i := 0; i < 100; i++ {
		mu, err := saferith_utils.NatRandomBits(crand.Reader, 512)
		require.NoError(t, err)
		w1, w2, w3, w4, err := numutils.GetFourSquares(crand.Reader, mu)
		require.NoError(t, err)
		ok := verify(mu, w1, w2, w3, w4)
		require.True(t, ok)
	}
}

func Test_FourSquares1024(t *testing.T) {
	t.Parallel()
	for i := 0; i < 50; i++ {
		mu, err := saferith_utils.NatRandomBits(crand.Reader, 1024)
		require.NoError(t, err)
		w1, w2, w3, w4, err := numutils.GetFourSquares(crand.Reader, mu)
		require.NoError(t, err)
		ok := verify(mu, w1, w2, w3, w4)
		require.True(t, ok)
	}
}

func Test_FourSquares2048(t *testing.T) {
	t.Parallel()
	t.Skip("timeouts now")
	if testing.Short() {
		t.Skip("skipping 2048 bits test")
	}
	for i := 0; i < 50; i++ {
		mu, err := saferith_utils.NatRandomBits(crand.Reader, 2048)
		require.NoError(t, err)
		w1, w2, w3, w4, err := numutils.GetFourSquares(crand.Reader, mu)
		require.NoError(t, err)
		ok := verify(mu, w1, w2, w3, w4)
		require.True(t, ok)
	}
}

func Test_FourSquares4096(t *testing.T) {
	t.Parallel()
	t.Skip("timeouts now")
	if testing.Short() {
		t.Skip("skipping 4096 bits test")
	}
	for i := 0; i < 1; i++ {
		mu, err := saferith_utils.NatRandomBits(crand.Reader, 4096)
		require.NoError(t, err)
		w1, w2, w3, w4, err := numutils.GetFourSquares(crand.Reader, mu)
		require.NoError(t, err)
		ok := verify(mu, w1, w2, w3, w4)
		require.True(t, ok)
	}
}

func BenchmarkFourSquare(b *testing.B) {
	const bits = 1024

	for i := 0; i < b.N; i++ {
		mu, _ := saferith_utils.NatRandomBits(crand.Reader, bits)
		_, _, _, _, _ = numutils.GetFourSquares(crand.Reader, mu)
	}
}
