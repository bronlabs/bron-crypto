package lp_test

import (
	"bytes"
	crand "crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/paillier"
	"github.com/copperexchange/knox-primitives/pkg/proofs/paillier/lp"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/merlin"
)

func doProof(k int, pk *paillier.PublicKey, sk *paillier.SecretKey) (err error) {
	prng := crand.Reader
	sessionId := []byte("lpSession")
	transcriptLabel := "LP"

	verifierTranscript := merlin.NewTranscript(transcriptLabel)
	verifier, err := lp.NewVerifier(k, pk, sessionId, verifierTranscript, prng)
	if err != nil {
		return err
	}

	proverTranscript := merlin.NewTranscript(transcriptLabel)
	prover, err := lp.NewProver(k, sk, sessionId, proverTranscript, prng)
	if err != nil {
		return err
	}

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

	err = verifier.Round5(r4)
	if err != nil {
		return err
	}

	label := "gimme, gimme"
	proverBytes := proverTranscript.ExtractBytes(label, 128)
	verifierBytes := verifierTranscript.ExtractBytes(label, 128)
	if !bytes.Equal(proverBytes, verifierBytes) {
		return errs.NewFailed("transcript record different data")
	}

	return nil
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
