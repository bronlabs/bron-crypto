package paillierrange_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/internal"
	"github.com/copperexchange/knox-primitives/pkg/paillier"
	paillierrange "github.com/copperexchange/knox-primitives/pkg/proofs/paillier/range"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

func Test_MeasureConstantTime_round1(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	prng := crand.Reader
	pk, _, err := paillier.NewKeys(128)
	require.NoError(t, err)
	q := new(saferith.Nat).SetUint64(3_000_000)
	sid := []byte("sessionId")
	x, err := randomIntInRange(q, prng)
	require.NoError(t, err)
	xEncrypted, _, err := pk.Encrypt(x)
	require.NoError(t, err)
	appLabel := "Range"
	var verifier *paillierrange.Verifier

	internal.RunMeasurement(500, "paillierrange_round1", func(i int) {
		verifierTranscript := hagrid.NewTranscript(appLabel)
		verifier, err = paillierrange.NewVerifier(128, q, sid, pk, xEncrypted, sid, verifierTranscript, prng)
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
	pk, sk, err := paillier.NewKeys(128)
	require.NoError(t, err)
	q := new(saferith.Nat).SetUint64(3_000_000)
	sid := []byte("sessionId")
	x, err := randomIntInRange(q, prng)
	require.NoError(t, err)
	xEncrypted, r, err := pk.Encrypt(x)
	require.NoError(t, err)
	appLabel := "Range"
	var verifier *paillierrange.Verifier
	var prover *paillierrange.Prover
	var r1 *paillierrange.Round1Output

	internal.RunMeasurement(500, "paillierrange_round2", func(i int) {
		verifierTranscript := hagrid.NewTranscript(appLabel)
		verifier, err = paillierrange.NewVerifier(128, q, sid, pk, xEncrypted, sid, verifierTranscript, prng)
		require.NoError(t, err)
		proverTranscript := hagrid.NewTranscript(appLabel)
		prover, err = paillierrange.NewProver(128, q, sid, sk, x, r, sid, proverTranscript, prng)
		require.NoError(t, err)
		r1, err = verifier.Round1()
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
	pk, sk, err := paillier.NewKeys(128)
	require.NoError(t, err)
	q := new(saferith.Nat).SetUint64(3_000_000)
	sid := []byte("sessionId")
	x, err := randomIntInRange(q, prng)
	require.NoError(t, err)
	xEncrypted, r, err := pk.Encrypt(x)
	require.NoError(t, err)
	appLabel := "Range"
	var verifier *paillierrange.Verifier
	var prover *paillierrange.Prover
	var r1 *paillierrange.Round1Output
	var r2 *paillierrange.ProverRound2Output

	internal.RunMeasurement(500, "paillierrange_round3", func(i int) {
		verifierTranscript := hagrid.NewTranscript(appLabel)
		verifier, err = paillierrange.NewVerifier(128, q, sid, pk, xEncrypted, sid, verifierTranscript, prng)
		require.NoError(t, err)
		proverTranscript := hagrid.NewTranscript(appLabel)
		prover, err = paillierrange.NewProver(128, q, sid, sk, x, r, sid, proverTranscript, prng)
		require.NoError(t, err)
		r1, err = verifier.Round1()
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
	pk, sk, err := paillier.NewKeys(128)
	require.NoError(t, err)
	q := new(saferith.Nat).SetUint64(3_000_000)
	sid := []byte("sessionId")
	x, err := randomIntInRange(q, prng)
	require.NoError(t, err)
	xEncrypted, r, err := pk.Encrypt(x)
	require.NoError(t, err)
	appLabel := "Range"
	var verifier *paillierrange.Verifier
	var prover *paillierrange.Prover
	var r1 *paillierrange.Round1Output
	var r2 *paillierrange.ProverRound2Output
	var r3 *paillierrange.VerifierRound3Output

	internal.RunMeasurement(500, "paillierrange_round4", func(i int) {
		verifierTranscript := hagrid.NewTranscript(appLabel)
		verifier, err = paillierrange.NewVerifier(128, q, sid, pk, xEncrypted, sid, verifierTranscript, prng)
		require.NoError(t, err)
		proverTranscript := hagrid.NewTranscript(appLabel)
		prover, err = paillierrange.NewProver(128, q, sid, sk, x, r, sid, proverTranscript, prng)
		require.NoError(t, err)
		r1, err = verifier.Round1()
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
	pk, sk, err := paillier.NewKeys(128)
	require.NoError(t, err)
	q := new(saferith.Nat).SetUint64(3_000_000)
	sid := []byte("sessionId")
	x, err := randomIntInRange(q, prng)
	require.NoError(t, err)
	xEncrypted, r, err := pk.Encrypt(x)
	require.NoError(t, err)
	appLabel := "Range"
	var verifier *paillierrange.Verifier
	var prover *paillierrange.Prover
	var r1 *paillierrange.Round1Output
	var r2 *paillierrange.ProverRound2Output
	var r3 *paillierrange.VerifierRound3Output
	var r4 *paillierrange.Round4Output

	internal.RunMeasurement(500, "paillierrange_round5", func(i int) {
		verifierTranscript := hagrid.NewTranscript(appLabel)
		verifier, err = paillierrange.NewVerifier(128, q, sid, pk, xEncrypted, sid, verifierTranscript, prng)
		require.NoError(t, err)
		proverTranscript := hagrid.NewTranscript(appLabel)
		prover, err = paillierrange.NewProver(128, q, sid, sk, x, r, sid, proverTranscript, prng)
		require.NoError(t, err)
		r1, err = verifier.Round1()
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
