package nthroots_test

import (
	crand "crypto/rand"
	"io"
	"os"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/internal"
	"github.com/bronlabs/krypton-primitives/pkg/base/modular"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/paillier/nthroots"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma"
)

func Test_MeasureConstantTime_round1(t *testing.T) {
	t.Parallel()
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
	bigN, err := modular.NewCrtResidueParams(p, 1, q, 1)
	require.NoError(t, err)
	bigNSquared, err := modular.NewCrtResidueParams(p, 2, q, 2)
	require.NoError(t, err)
	yInt, err := crand.Int(prng, bigN.GetModulus().Big())
	require.NoError(t, err)
	y := new(saferith.Nat).SetBig(yInt, 256)
	require.NoError(t, err)
	x := new(saferith.Nat).Exp(y, bigN.GetModulus().Nat(), bigNSquared.GetModulus())
	var proto sigma.Protocol[nthroots.Statement, nthroots.Witness, nthroots.Commitment, nthroots.State, nthroots.Response]

	internal.RunMeasurement(500, "nthroot_round1", func(i int) {
		proto, err = nthroots.NewSigmaProtocol(bigN, bigNSquared, 1, prng)
		require.NoError(t, err)
	}, func() {
		_, _, _ = proto.ComputeProverCommitment([]*saferith.Nat{x}, []*saferith.Nat{y})
	})
}

func Test_MeasureConstantTime_round2(t *testing.T) {
	t.Parallel()
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
	bigN, err := modular.NewCrtResidueParams(p, 1, q, 1)
	require.NoError(t, err)
	bigNSquared, err := modular.NewCrtResidueParams(p, 2, q, 2)
	require.NoError(t, err)
	yInt, err := crand.Int(prng, bigN.GetModulus().Big())
	require.NoError(t, err)
	y := new(saferith.Nat).SetBig(yInt, 256)
	require.NoError(t, err)
	x := new(saferith.Nat).Exp(y, bigN.GetModulus().Nat(), bigNSquared.GetModulus())
	var proto sigma.Protocol[nthroots.Statement, nthroots.Witness, nthroots.Commitment, nthroots.State, nthroots.Response]
	var a nthroots.Commitment
	var s nthroots.State
	var e []byte

	internal.RunMeasurement(500, "nthroot_round2", func(i int) {
		proto, err := nthroots.NewSigmaProtocol(bigN, bigNSquared, 1, prng)
		require.NoError(t, err)
		a, s, err = proto.ComputeProverCommitment([]*saferith.Nat{x}, []*saferith.Nat{y})
		require.NoError(t, err)
		e := make([]byte, i)
		_, err = io.ReadFull(prng, e)
		require.NoError(t, err)
	}, func() {
		_, _ = proto.ComputeProverResponse([]*saferith.Nat{x}, []*saferith.Nat{y}, a, s, e)
	})
}

func Test_MeasureConstantTime_round3(t *testing.T) {
	t.Parallel()
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
	bigN, err := modular.NewCrtResidueParams(p, 1, q, 1)
	require.NoError(t, err)
	bigNSquared, err := modular.NewCrtResidueParams(p, 2, q, 2)
	require.NoError(t, err)
	yInt, err := crand.Int(prng, bigN.GetModulus().Big())
	require.NoError(t, err)
	y := new(saferith.Nat).SetBig(yInt, 256)
	require.NoError(t, err)
	x := new(saferith.Nat).Exp(y, bigN.GetModulus().Nat(), bigNSquared.GetModulus())
	var proto sigma.Protocol[nthroots.Statement, nthroots.Witness, nthroots.Commitment, nthroots.State, nthroots.Response]
	var a nthroots.Commitment
	var s nthroots.State
	var e []byte
	var z nthroots.Response

	internal.RunMeasurement(500, "nthroot_round2", func(i int) {
		proto, err := nthroots.NewSigmaProtocol(bigN, bigNSquared, 1, prng)
		require.NoError(t, err)
		a, s, err = proto.ComputeProverCommitment([]*saferith.Nat{x}, []*saferith.Nat{y})
		require.NoError(t, err)
		e = make([]byte, i)
		_, err = io.ReadFull(prng, e)
		require.NoError(t, err)
		z, err = proto.ComputeProverResponse([]*saferith.Nat{x}, []*saferith.Nat{y}, a, s, e)
		require.NoError(t, err)
	}, func() {
		_ = proto.Verify([]*saferith.Nat{x}, a, e, z)
	})
}
