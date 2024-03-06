package nthroot_test

import (
	crand "crypto/rand"
	"io"
	"os"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/internal"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/nthroot"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
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
	var proto sigma.Protocol[nthroot.Statement, nthroot.Witness, nthroot.Commitment, nthroot.State, nthroot.Response]

	internal.RunMeasurement(500, "nthroot_round1", func(i int) {
		proto, err = nthroot.NewSigmaProtocol(bigN, prng)
		require.NoError(t, err)
	}, func() {
		_, _, _ = proto.ComputeProverCommitment(x, y)
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
	var proto sigma.Protocol[nthroot.Statement, nthroot.Witness, nthroot.Commitment, nthroot.State, nthroot.Response]
	var a nthroot.Commitment
	var s nthroot.State
	var e []byte

	internal.RunMeasurement(500, "nthroot_round2", func(i int) {
		proto, err := nthroot.NewSigmaProtocol(bigN, prng)
		require.NoError(t, err)
		a, s, err = proto.ComputeProverCommitment(x, y)
		require.NoError(t, err)
		e := make([]byte, i)
		_, err = io.ReadFull(prng, e)
		require.NoError(t, err)
	}, func() {
		_, _ = proto.ComputeProverResponse(x, y, a, s, e)
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
	var proto sigma.Protocol[nthroot.Statement, nthroot.Witness, nthroot.Commitment, nthroot.State, nthroot.Response]
	var a nthroot.Commitment
	var s nthroot.State
	var e []byte
	var z nthroot.Response

	internal.RunMeasurement(500, "nthroot_round2", func(i int) {
		proto, err := nthroot.NewSigmaProtocol(bigN, prng)
		require.NoError(t, err)
		a, s, err = proto.ComputeProverCommitment(x, y)
		require.NoError(t, err)
		e = make([]byte, i)
		_, err = io.ReadFull(prng, e)
		require.NoError(t, err)
		z, err = proto.ComputeProverResponse(x, y, a, s, e)
		require.NoError(t, err)
	}, func() {
		_ = proto.Verify(x, a, e, z)
	})
}
