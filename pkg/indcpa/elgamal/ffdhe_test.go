package elgamal_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/indcpa/elgamal"
)

func Test_Sanity(t *testing.T) {
	t.Parallel()

	require.True(t, elgamal.Ffdhe2048Modulus.Big().ProbablyPrime(2))
	require.True(t, elgamal.Ffdhe2048Order.Big().ProbablyPrime(2))
	require.True(t, big.Jacobi(elgamal.Ffdhe2048Generator.Big(), elgamal.Ffdhe2048Modulus.Big()) == 1)
}
