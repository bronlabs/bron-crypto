package prob_prime

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_QSanity(t *testing.T) {
	const maxPrimeBitLen = 2048
	const maxNoOfParties = 64

	// 64 is the max number of supported parties
	require.True(t, ParamQ.BitLen() > ((2*maxPrimeBitLen)+maxNoOfParties))
	require.True(t, ParamQ.ProbablyPrime(2))
}
