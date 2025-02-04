package feldman_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/internal"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/dlog/batch_schnorr"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler/fischlin"
	compilerUtils "github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler_utils"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/feldman"
)

func Test_MeasureConstantTime_split(t *testing.T) {
	t.Parallel()
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	th := 3
	curve := k256.NewCurve()
	scheme, err := feldman.NewDealer(uint(th), 5, curve)
	require.NoError(t, err)
	var secret curves.Scalar
	var prover compiler.NIProver[batch_schnorr.Statement, batch_schnorr.Witness]
	protocol, err := batch_schnorr.NewSigmaProtocol(uint(th), curve.Generator(), crand.Reader)
	require.NoError(t, err)
	comp, err := compilerUtils.MakeNonInteractive(fischlin.Name, protocol, crand.Reader)
	require.NoError(t, err)
	internal.RunMeasurement(32*8, "feldman_split", func(i int) {
		secret, err = curve.ScalarField().Hash(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
		prover, err = comp.NewProver([]byte("test"), nil)
		require.NoError(t, err)
	}, func() {
		_, _, _, _ = scheme.Split(secret, prover, crand.Reader)
	})
}

func Test_MeasureConstantTime_verify(t *testing.T) {
	t.Parallel()
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	th := 3
	curve := k256.NewCurve()
	scheme, err := feldman.NewDealer(uint(th), 5, curve)
	require.NoError(t, err)
	var secret curves.Scalar
	var commitments []curves.Point
	var shares []*feldman.Share
	var proof compiler.NIZKPoKProof
	var verifier compiler.NIVerifier[batch_schnorr.Statement]
	protocol, err := batch_schnorr.NewSigmaProtocol(uint(th), curve.Generator(), crand.Reader)
	require.NoError(t, err)
	comp, err := compilerUtils.MakeNonInteractive(fischlin.Name, protocol, crand.Reader)
	require.NoError(t, err)
	internal.RunMeasurement(32*8, "feldman_verify", func(i int) {
		secret, err = curve.ScalarField().Hash(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
		prover, err := comp.NewProver([]byte("test"), nil)
		require.NoError(t, err)
		verifier, err = comp.NewVerifier([]byte("test"), nil)
		require.NoError(t, err)
		commitments, shares, proof, err = scheme.Split(secret, prover, crand.Reader)
		require.NoError(t, err)
	}, func() {
		_ = feldman.Verify(shares[0], commitments, verifier, proof)
	})
}

func Test_MeasureConstantTime_combine(t *testing.T) {
	t.Parallel()
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	th := 3
	curve := k256.NewCurve()
	scheme, err := feldman.NewDealer(uint(th), 5, curve)
	require.NoError(t, err)
	var secret curves.Scalar
	var shares []*feldman.Share
	protocol, err := batch_schnorr.NewSigmaProtocol(uint(th), curve.Generator(), crand.Reader)
	require.NoError(t, err)
	comp, err := compilerUtils.MakeNonInteractive(fischlin.Name, protocol, crand.Reader)
	require.NoError(t, err)
	internal.RunMeasurement(32*8, "feldman_combine", func(i int) {
		secret, err = curve.ScalarField().Hash(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
		prover, err := comp.NewProver([]byte("test"), nil)
		require.NoError(t, err)
		_, shares, _, err = scheme.Split(secret, prover, crand.Reader)
		require.NoError(t, err)
	}, func() {
		_, _ = scheme.Combine(shares[0], shares[0], shares[1])
	})
}
