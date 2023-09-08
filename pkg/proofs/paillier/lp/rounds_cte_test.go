package lp_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton/internal"
	"github.com/copperexchange/krypton/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton/pkg/proofs/paillier/lp"
	"github.com/copperexchange/krypton/pkg/transcripts/hagrid"
)

func Test_MeasureConstantTime_round1(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	prng := crand.Reader
	pInt, err := crand.Prime(prng, 256)
	require.NoError(t, err)
	p := new(saferith.Nat).SetBig(pInt, 256)
	qInt, err := crand.Prime(prng, 256)
	require.NoError(t, err)
	q := new(saferith.Nat).SetBig(qInt, 256)
	require.NoError(t, err)
	var sk *paillier.SecretKey
	require.NoError(t, err)
	sessionId := []byte("lpSession")
	transcriptLabel := "LP"
	verifierTranscript := hagrid.NewTranscript(transcriptLabel, nil)
	var verifier *lp.Verifier

	internal.RunMeasurement(100, "paillier_lp_round1", func(i int) {
		sk, err = paillier.NewSecretKey(p, q)
		require.NoError(t, err)
		verifier, err = lp.NewVerifier(128, &sk.PublicKey, sessionId, verifierTranscript, prng)
		require.NoError(t, err)
	}, func() {
		verifier.Round1()
	})
}

func Test_MeasureConstantTime_round2(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	prng := crand.Reader
	pInt, err := crand.Prime(prng, 256)
	require.NoError(t, err)
	p := new(saferith.Nat).SetBig(pInt, 256)
	qInt, err := crand.Prime(prng, 256)
	require.NoError(t, err)
	q := new(saferith.Nat).SetBig(qInt, 256)
	require.NoError(t, err)
	var sk *paillier.SecretKey
	require.NoError(t, err)
	sessionId := []byte("lpSession")
	transcriptLabel := "LP"
	verifierTranscript := hagrid.NewTranscript(transcriptLabel, nil)
	proverTranscript := hagrid.NewTranscript(transcriptLabel, nil)
	var verifier *lp.Verifier
	var r1 *lp.Round1Output
	var prover *lp.Prover
	internal.RunMeasurement(100, "paillier_lp_round2", func(i int) {
		sk, err = paillier.NewSecretKey(p, q)
		require.NoError(t, err)
		verifier, err = lp.NewVerifier(128, &sk.PublicKey, sessionId, verifierTranscript, prng)
		require.NoError(t, err)
		r1, err = verifier.Round1()
		require.NoError(t, err)
		prover, err = lp.NewProver(128, sk, sessionId, proverTranscript, prng)
		require.NoError(t, err)
	}, func() {
		prover.Round2(r1)
	})
}

func Test_MeasureConstantTime_round3(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	prng := crand.Reader
	pInt, err := crand.Prime(prng, 256)
	require.NoError(t, err)
	p := new(saferith.Nat).SetBig(pInt, 256)
	qInt, err := crand.Prime(prng, 256)
	require.NoError(t, err)
	q := new(saferith.Nat).SetBig(qInt, 256)
	require.NoError(t, err)
	var sk *paillier.SecretKey
	require.NoError(t, err)
	sessionId := []byte("lpSession")
	transcriptLabel := "LP"
	verifierTranscript := hagrid.NewTranscript(transcriptLabel, nil)
	proverTranscript := hagrid.NewTranscript(transcriptLabel, nil)
	var verifier *lp.Verifier
	var r1 *lp.Round1Output
	var prover *lp.Prover
	var r2 *lp.Round2Output
	internal.RunMeasurement(100, "paillier_lp_round3", func(i int) {
		sk, err = paillier.NewSecretKey(p, q)
		require.NoError(t, err)
		verifier, err = lp.NewVerifier(128, &sk.PublicKey, sessionId, verifierTranscript, prng)
		require.NoError(t, err)
		r1, err = verifier.Round1()
		require.NoError(t, err)
		prover, err = lp.NewProver(128, sk, sessionId, proverTranscript, prng)
		require.NoError(t, err)
		r2, err = prover.Round2(r1)
		require.NoError(t, err)
	}, func() {
		verifier.Round3(r2)
	})
}

func Test_MeasureConstantTime_round4(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	prng := crand.Reader
	pInt, err := crand.Prime(prng, 256)
	require.NoError(t, err)
	p := new(saferith.Nat).SetBig(pInt, 256)
	qInt, err := crand.Prime(prng, 256)
	require.NoError(t, err)
	q := new(saferith.Nat).SetBig(qInt, 256)
	require.NoError(t, err)
	var sk *paillier.SecretKey
	require.NoError(t, err)
	sessionId := []byte("lpSession")
	transcriptLabel := "LP"
	verifierTranscript := hagrid.NewTranscript(transcriptLabel, nil)
	proverTranscript := hagrid.NewTranscript(transcriptLabel, nil)
	var verifier *lp.Verifier
	var r1 *lp.Round1Output
	var prover *lp.Prover
	var r2 *lp.Round2Output
	var r3 *lp.Round3Output
	internal.RunMeasurement(100, "paillier_lp_round4", func(i int) {
		sk, err = paillier.NewSecretKey(p, q)
		require.NoError(t, err)
		verifier, err = lp.NewVerifier(128, &sk.PublicKey, sessionId, verifierTranscript, prng)
		require.NoError(t, err)
		r1, err = verifier.Round1()
		require.NoError(t, err)
		prover, err = lp.NewProver(128, sk, sessionId, proverTranscript, prng)
		require.NoError(t, err)
		r2, err = prover.Round2(r1)
		require.NoError(t, err)
		r3, err = verifier.Round3(r2)
		require.NoError(t, err)
	}, func() {
		prover.Round4(r3)
	})
}

func Test_MeasureConstantTime_round5(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	prng := crand.Reader
	pInt, err := crand.Prime(prng, 256)
	require.NoError(t, err)
	p := new(saferith.Nat).SetBig(pInt, 256)
	qInt, err := crand.Prime(prng, 256)
	require.NoError(t, err)
	q := new(saferith.Nat).SetBig(qInt, 256)
	require.NoError(t, err)
	var sk *paillier.SecretKey
	require.NoError(t, err)
	sessionId := []byte("lpSession")
	transcriptLabel := "LP"
	verifierTranscript := hagrid.NewTranscript(transcriptLabel, nil)
	proverTranscript := hagrid.NewTranscript(transcriptLabel, nil)
	var verifier *lp.Verifier
	var r1 *lp.Round1Output
	var prover *lp.Prover
	var r2 *lp.Round2Output
	var r3 *lp.Round3Output
	var r4 *lp.Round4Output
	internal.RunMeasurement(100, "paillier_lp_round5", func(i int) {
		sk, err = paillier.NewSecretKey(p, q)
		require.NoError(t, err)
		verifier, err = lp.NewVerifier(128, &sk.PublicKey, sessionId, verifierTranscript, prng)
		require.NoError(t, err)
		r1, err = verifier.Round1()
		require.NoError(t, err)
		prover, err = lp.NewProver(128, sk, sessionId, proverTranscript, prng)
		require.NoError(t, err)
		r2, err = prover.Round2(r1)
		require.NoError(t, err)
		r3, err = verifier.Round3(r2)
		require.NoError(t, err)
		r4, err = prover.Round4(r3)
		require.NoError(t, err)
	}, func() {
		verifier.Round5(r4)
	})
}
