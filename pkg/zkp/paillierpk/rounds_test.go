package paillierpk_test

import (
	crand "crypto/rand"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/paillier"
	"github.com/copperexchange/crypto-primitives-go/pkg/zkp/paillierpk"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func doProof(k int, pk *paillier.PublicKey, sk *paillier.SecretKey) (err error) {
	prng := crand.Reader
	verifier := paillierpk.NewVerifier(k, pk, prng)
	prover := paillierpk.NewProver(k, sk, prng)

	r1, err := verifier.Round1()
	if err != nil {
		return err
	}

	r2, err := prover.Round2(r1)
	if err != nil {
		return err
	}

	r3, err := verifier.Round3(r2)
	if err != nil {
		return err
	}

	r4, err := prover.Round4(r3)
	if err != nil {
		return err
	}

	return verifier.Round5(r4)
}

func Test_HappyPath(t *testing.T) {
	prng := crand.Reader
	p, err := crand.Prime(prng, 256)
	require.NoError(t, err)
	q, err := crand.Prime(prng, 256)
	require.NoError(t, err)

	sk, err := paillier.NewSecretKey(p, q)
	require.NoError(t, err)

	err = doProof(40, &sk.PublicKey, sk)
	require.NoError(t, err)
}

func Test_IncorrectPublicKey(t *testing.T) {
	prng := crand.Reader
	p1, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	p2, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	q, err := crand.Prime(prng, 256)
	require.NoError(t, err)

	// p is not a prime number
	p := new(big.Int).Mul(p1, p2)
	sk, err := paillier.NewSecretKey(p, q)
	require.NoError(t, err)

	err = doProof(128, &sk.PublicKey, sk)
	require.Error(t, err)
	require.True(t, errs.IsVerificationFailed(err))
}
