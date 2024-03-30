package saferith_ex_test

import (
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/saferith_ex"
)

func Test_SafePrimePairGen(t *testing.T) {
	p, q, err := saferith_ex.GenSafePrimePair(1024)
	require.NoError(t, err)

	pHalf := new(saferith.Nat).Rsh(p, 1, -1)
	qHalf := new(saferith.Nat).Rsh(q, 1, -1)

	require.Equal(t, p.TrueLen(), 1024)
	require.Equal(t, q.TrueLen(), 1024)
	require.True(t, p.Big().ProbablyPrime(64))
	require.True(t, q.Big().ProbablyPrime(64))
	require.True(t, pHalf.Big().ProbablyPrime(64))
	require.True(t, qHalf.Big().ProbablyPrime(64))
}
