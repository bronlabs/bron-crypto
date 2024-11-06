package prob_prime_two_three

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_QSanity(t *testing.T) {
	const primeBitLen = 2048

	require.True(t, ParamQ.BitLen() > ((2*primeBitLen)+3))
	require.True(t, ParamQ.ProbablyPrime(2))
}
