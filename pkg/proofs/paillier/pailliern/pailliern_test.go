package pailliern_test

import (
	crand "crypto/rand"
	"fmt"
	"math/big"
	"slices"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/pailliern"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

func Test_pIsCorrect(t *testing.T) {
	t.Parallel()

	pCheck := new(saferith.Nat).SetUint64(1)
	for i := 2; i < pailliern.Alpha; i++ {
		if isPrime(i) {
			pCheck = new(saferith.Nat).Mul(pCheck, new(saferith.Nat).SetUint64(uint64(i)), pailliern.P.AnnouncedLen())
		}
	}

	_, eq, _ := pCheck.Cmp(pailliern.P)
	require.Equal(t, eq, saferith.Choice(1))
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	label := "NizkPaillierNTranscriptLabel"
	sessionId := "NizkPaillierNTestSessionId"

	proverTranscript := hagrid.NewTranscript(label, nil)
	verifierTranscript := hagrid.NewTranscript(label, nil)

	for i := 0; i < 32; i++ {
		sid := fmt.Sprintf("%s_%d", sessionId, i)

		pInt, err := crand.Prime(prng, 512)
		require.NoError(t, err)
		p := new(saferith.Nat).SetBig(pInt, 512)
		qInt, err := crand.Prime(prng, 512)
		require.NoError(t, err)
		q := new(saferith.Nat).SetBig(qInt, 512)

		sk, err := paillier.NewSecretKey(p, q)
		require.NoError(t, err)

		prover, err := pailliern.NewProver([]byte(sid), proverTranscript)
		require.NoError(t, err)

		proof, _, err := prover.Prove(sk)
		require.NoError(t, err)
		require.NotNil(t, proof)

		err = pailliern.Verify([]byte(sid), verifierTranscript, &sk.PublicKey, proof)
		require.NoError(t, err)
	}

	proverBytes, err := proverTranscript.ExtractBytes("test", 16)
	require.NoError(t, err)
	verifierBytes, err := verifierTranscript.ExtractBytes("test", 16)
	require.NoError(t, err)

	require.True(t, slices.Equal(proverBytes, verifierBytes))
}

func Test_InvalidStatement(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	label := "NizkPaillierNTranscriptLabel"
	sessionId := "NizkPaillierNTestSessionId"

	proverTranscript := hagrid.NewTranscript(label, nil)
	verifierTranscript := hagrid.NewTranscript(label, nil)

	for i := 0; i < 32; i++ {
		sid := fmt.Sprintf("%s_%d", sessionId, i)

		pInt, err := crand.Prime(prng, 512)
		require.NoError(t, err)
		p := new(saferith.Nat).SetBig(pInt, 512)

		pMinusOne := new(saferith.Nat).Sub(p, new(saferith.Nat).SetUint64(1), 512)
		n := new(saferith.Nat).Mul(p, p, 1024) // n = p^2
		totient := new(saferith.Nat).Mul(p, pMinusOne, 1024)

		// try to forge paillier keys by introducing square of prime
		sk := &paillier.SecretKey{
			PublicKey: paillier.PublicKey{
				N: n,
			},
			Phi: totient,
		}

		prover, err := pailliern.NewProver([]byte(sid), proverTranscript)
		require.NoError(t, err)

		proof, _, err := prover.Prove(sk)
		require.NoError(t, err)
		require.NotNil(t, proof)

		err = pailliern.Verify([]byte(sid), verifierTranscript, &sk.PublicKey, proof)
		require.Error(t, err)
		require.True(t, errs.IsVerification(err))
	}

	proverBytes, err := proverTranscript.ExtractBytes("test", 16)
	require.NoError(t, err)
	verifierBytes, err := verifierTranscript.ExtractBytes("test", 16)
	require.NoError(t, err)

	require.True(t, slices.Equal(proverBytes, verifierBytes))
}

func isPrime(x int) bool {
	return big.NewInt(int64(x)).ProbablyPrime(32)
}
