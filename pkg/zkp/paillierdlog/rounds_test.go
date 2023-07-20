package paillierdlog_test

import (
	crand "crypto/rand"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/paillier"
	"github.com/copperexchange/crypto-primitives-go/pkg/zkp/paillierdlog"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_HappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	prng := crand.Reader
	curve := curves.P256()

	x := curve.NewScalar().Random(prng)
	bigQ := curve.ScalarBaseMult(x)
	pk, sk, err := paillier.NewKeys(1024)
	require.NoError(t, err)
	xEncrypted, _, err := pk.Encrypt(x.BigInt())
	require.NoError(t, err)

	verifier, err := paillierdlog.NewVerifier(xEncrypted, pk, bigQ, prng)
	require.NoError(t, err)
	prover, err := paillierdlog.NewProver(x, sk)
	require.NoError(t, err)

	r1, err := verifier.Round1()
	require.NoError(t, err)

	r2, err := prover.Round2(r1)
	require.NoError(t, err)

	r3 := verifier.Round3(r2)
	r4, err := prover.Round4(r3)
	require.NoError(t, err)

	err = verifier.Round5(r4)
	require.NoError(t, err)
}

func Test_UnhappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	prng := crand.Reader
	curve := curves.P256()

	x := curve.NewScalar().Random(prng)
	bigQ := curve.ScalarBaseMult(curve.NewScalar().Random(prng))
	pk, sk, err := paillier.NewKeys(1024)
	require.NoError(t, err)
	xEncrypted, _, err := pk.Encrypt(x.BigInt())
	require.NoError(t, err)

	verifier, err := paillierdlog.NewVerifier(xEncrypted, pk, bigQ, prng)
	require.NoError(t, err)
	prover, err := paillierdlog.NewProver(x, sk)
	require.NoError(t, err)

	r1, err := verifier.Round1()
	require.NoError(t, err)

	r2, err := prover.Round2(r1)
	require.NoError(t, err)

	r3 := verifier.Round3(r2)
	r4, err := prover.Round4(r3)
	require.NoError(t, err)

	err = verifier.Round5(r4)
	require.Error(t, err)
}
