package elgamal_test

import (
	"github.com/bronlabs/krypton-primitives/pkg/indcpa/elgamal"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func Test_Sanity(t *testing.T) {
	require.True(t, elgamal.Ffdhe2048Modulus.Big().ProbablyPrime(2))
	require.True(t, elgamal.Ffdhe2048Order.Big().ProbablyPrime(2))
	require.True(t, big.Jacobi(elgamal.Ffdhe2048Generator.Big(), elgamal.Ffdhe2048Modulus.Big()) == 1)
}
