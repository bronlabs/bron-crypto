package nthroot_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/internal"
	"github.com/copperexchange/knox-primitives/pkg/proofs/paillier/nthroot"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

func Test_MeasureConstantTime_round1(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	prng := crand.Reader
	pInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	p := new(saferith.Nat).SetBig(pInt, 128)
	qInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	q := new(saferith.Nat).SetBig(qInt, 128)
	require.NoError(t, err)
	bigN := new(saferith.Nat).Mul(p, q, 256)
	bigNSquared := saferith.ModulusFromNat(new(saferith.Nat).Mul(bigN, bigN, 512))
	yInt, err := crand.Int(prng, bigN.Big())
	require.NoError(t, err)
	y := new(saferith.Nat).SetBig(yInt, 256)
	require.NoError(t, err)
	x := new(saferith.Nat).Exp(y, bigN, bigNSquared)
	sessionId := []byte("nthRootSession")
	appLabel := "NthRoot"
	proverTranscript := hagrid.NewTranscript(appLabel)
	var prover *nthroot.Prover

	internal.RunMeasurement(500, "nthroot_round1", func(i int) {
		prover, err = nthroot.NewProver(bigN, x, y, sessionId, proverTranscript, prng)
		require.NoError(t, err)
	}, func() {
		prover.Round1()
	})
}

func Test_MeasureConstantTime_round2(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	prng := crand.Reader
	pInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	p := new(saferith.Nat).SetBig(pInt, 128)
	qInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	q := new(saferith.Nat).SetBig(qInt, 128)
	require.NoError(t, err)
	bigN := new(saferith.Nat).Mul(p, q, 256)
	bigNSquared := saferith.ModulusFromNat(new(saferith.Nat).Mul(bigN, bigN, 512))
	yInt, err := crand.Int(prng, bigN.Big())
	require.NoError(t, err)
	y := new(saferith.Nat).SetBig(yInt, 256)
	require.NoError(t, err)
	x := new(saferith.Nat).Exp(y, bigN, bigNSquared)
	sessionId := []byte("nthRootSession")
	appLabel := "NthRoot"
	proverTranscript := hagrid.NewTranscript(appLabel)
	var prover *nthroot.Prover
	verifierTranscript := hagrid.NewTranscript(appLabel)
	var verifier *nthroot.Verifier
	var r1 *nthroot.Round1Output
	internal.RunMeasurement(500, "nthroot_round2", func(i int) {
		prover, err = nthroot.NewProver(bigN, x, y, sessionId, proverTranscript, prng)
		require.NoError(t, err)
		verifier, err = nthroot.NewVerifier(bigN, x, sessionId, verifierTranscript, prng)
		require.NoError(t, err)
		r1, err = prover.Round1()
		require.NoError(t, err)
	}, func() {
		verifier.Round2(r1)
	})
}

func Test_MeasureConstantTime_round3(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	prng := crand.Reader
	pInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	p := new(saferith.Nat).SetBig(pInt, 128)
	qInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	q := new(saferith.Nat).SetBig(qInt, 128)
	require.NoError(t, err)
	bigN := new(saferith.Nat).Mul(p, q, 256)
	bigNSquared := saferith.ModulusFromNat(new(saferith.Nat).Mul(bigN, bigN, 512))
	yInt, err := crand.Int(prng, bigN.Big())
	require.NoError(t, err)
	y := new(saferith.Nat).SetBig(yInt, 256)
	require.NoError(t, err)
	x := new(saferith.Nat).Exp(y, bigN, bigNSquared)
	sessionId := []byte("nthRootSession")
	appLabel := "NthRoot"
	proverTranscript := hagrid.NewTranscript(appLabel)
	var prover *nthroot.Prover
	verifierTranscript := hagrid.NewTranscript(appLabel)
	var verifier *nthroot.Verifier
	var r1 *nthroot.Round1Output
	var r2 *nthroot.Round2Output
	internal.RunMeasurement(500, "nthroot_round3", func(i int) {
		prover, err = nthroot.NewProver(bigN, x, y, sessionId, proverTranscript, prng)
		require.NoError(t, err)
		verifier, err = nthroot.NewVerifier(bigN, x, sessionId, verifierTranscript, prng)
		require.NoError(t, err)
		r1, err = prover.Round1()
		require.NoError(t, err)
		r2, err = verifier.Round2(r1)
		require.NoError(t, err)
	}, func() {
		prover.Round3(r2)
	})
}

func Test_MeasureConstantTime_round4(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	prng := crand.Reader
	pInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	p := new(saferith.Nat).SetBig(pInt, 128)
	qInt, err := crand.Prime(prng, 128)
	require.NoError(t, err)
	q := new(saferith.Nat).SetBig(qInt, 128)
	require.NoError(t, err)
	bigN := new(saferith.Nat).Mul(p, q, 256)
	bigNSquared := saferith.ModulusFromNat(new(saferith.Nat).Mul(bigN, bigN, 512))
	yInt, err := crand.Int(prng, bigN.Big())
	require.NoError(t, err)
	y := new(saferith.Nat).SetBig(yInt, 256)
	require.NoError(t, err)
	x := new(saferith.Nat).Exp(y, bigN, bigNSquared)
	sessionId := []byte("nthRootSession")
	appLabel := "NthRoot"
	proverTranscript := hagrid.NewTranscript(appLabel)
	var prover *nthroot.Prover
	verifierTranscript := hagrid.NewTranscript(appLabel)
	var verifier *nthroot.Verifier
	var r1 *nthroot.Round1Output
	var r2 *nthroot.Round2Output
	var r3 *nthroot.Round3Output
	internal.RunMeasurement(500, "nthroot_round4", func(i int) {
		prover, err = nthroot.NewProver(bigN, x, y, sessionId, proverTranscript, prng)
		require.NoError(t, err)
		verifier, err = nthroot.NewVerifier(bigN, x, sessionId, verifierTranscript, prng)
		require.NoError(t, err)
		r1, err = prover.Round1()
		require.NoError(t, err)
		r2, err = verifier.Round2(r1)
		require.NoError(t, err)
		r3, err = prover.Round3(r2)
		require.NoError(t, err)
	}, func() {
		verifier.Round4(r3)
	})
}
