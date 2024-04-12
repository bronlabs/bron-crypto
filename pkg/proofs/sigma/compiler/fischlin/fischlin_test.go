package fischlin_test

import (
	"bytes"
	crand "crypto/rand"
	"strconv"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dleq/chaum"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/nthroot"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/fischlin"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler_utils"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

var supportedCurve = []curves.Curve{
	k256.NewCurve(),
	p256.NewCurve(),
	edwards25519.NewCurve(),
	pallas.NewCurve(),
	bls12381.NewG1(),
	bls12381.NewG2(),
}

func Test_HappyPathWithSchnorr(t *testing.T) {
	t.Parallel()

	for i, c := range supportedCurve {
		i := i
		curve := c
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			prng := crand.Reader
			sessionId := []byte("TestSessionId" + strconv.Itoa(i))

			schnorrProtocol, err := schnorr.NewSigmaProtocol(curve.Generator(), prng)
			require.NoError(t, err)

			nizk, err := compiler_utils.MakeNonInteractive(fischlin.Name, schnorrProtocol, prng)
			require.NoError(t, err)

			proverTranscript := hagrid.NewTranscript("Test"+strconv.Itoa(i), nil)
			prover, err := nizk.NewProver(sessionId, proverTranscript)
			require.NoError(t, err)
			require.NotNil(t, prover)

			verifierTranscript := hagrid.NewTranscript("Test"+strconv.Itoa(i), nil)
			verifier, err := nizk.NewVerifier(sessionId, verifierTranscript)
			require.NoError(t, err)
			require.NotNil(t, verifier)

			witness, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			statement := curve.ScalarBaseMult(witness)

			proof, err := prover.Prove(statement, witness)
			require.NoError(t, err)
			theProof, ok := proof.(*fischlin.Proof[schnorr.Commitment, schnorr.Response])
			require.True(t, ok)

			err = verifier.Verify(statement, theProof)
			require.NoError(t, err)

			proverBytes, err := proverTranscript.ExtractBytes("Bytes"+strconv.Itoa(i), 32)
			require.NoError(t, err)
			verifierBytes, err := verifierTranscript.ExtractBytes("Bytes"+strconv.Itoa(i), 32)
			require.NoError(t, err)

			require.True(t, bytes.Equal(proverBytes, verifierBytes))
		})
	}
}

func Test_HappyPathWithChaumPedersen(t *testing.T) {
	t.Parallel()

	for i, c := range supportedCurve {
		i := i
		curve := c
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			prng := crand.Reader
			sessionId := []byte("TestSessionId" + strconv.Itoa(i))

			g1, err := curve.Random(prng)
			require.NoError(t, err)
			g2, err := curve.Random(prng)
			require.NoError(t, err)

			chaumPedersenProtocol, err := chaum.NewSigmaProtocol(g1, g2, prng)
			require.NoError(t, err)

			nizk, err := compiler_utils.MakeNonInteractive(fischlin.Name, chaumPedersenProtocol, prng)
			require.NoError(t, err)

			proverTranscript := hagrid.NewTranscript("Test"+strconv.Itoa(i), nil)
			prover, err := nizk.NewProver(sessionId, proverTranscript)
			require.NoError(t, err)
			require.NotNil(t, prover)

			verifierTranscript := hagrid.NewTranscript("Test"+strconv.Itoa(i), nil)
			verifier, err := nizk.NewVerifier(sessionId, verifierTranscript)
			require.NoError(t, err)
			require.NotNil(t, verifier)

			scalar, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)

			witness := chaum.Witness(scalar)
			statement := &chaum.Statement{
				X1: g1.Mul(witness),
				X2: g2.Mul(witness),
			}

			proof, err := prover.Prove(statement, witness)
			require.NoError(t, err)
			theProof, ok := proof.(*fischlin.Proof[*chaum.Commitment, chaum.Response])
			require.True(t, ok)

			err = verifier.Verify(statement, theProof)
			require.NoError(t, err)

			proverBytes, err := proverTranscript.ExtractBytes("Bytes"+strconv.Itoa(i), 32)
			require.NoError(t, err)
			verifierBytes, err := verifierTranscript.ExtractBytes("Bytes"+strconv.Itoa(i), 32)
			require.NoError(t, err)

			require.True(t, bytes.Equal(proverBytes, verifierBytes))
		})
	}
}

func Test_HappyPathNthRoot(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	sessionId := []byte("TestSessionId")

	nBig, err := crand.Prime(prng, 1024)
	require.NoError(t, err)
	n := new(saferith.Nat).SetBig(nBig, 1024)
	nn := new(saferith.Nat).Mul(n, n, 2048)

	nthRootProtocol, err := nthroot.NewSigmaProtocol(n, prng)
	require.NoError(t, err)

	nizk, err := compiler_utils.MakeNonInteractive(fischlin.Name, nthRootProtocol, prng)
	require.NoError(t, err)

	proverTranscript := hagrid.NewTranscript("Test", nil)
	prover, err := nizk.NewProver(sessionId, proverTranscript)
	require.NoError(t, err)
	require.NotNil(t, prover)

	verifierTranscript := hagrid.NewTranscript("Test", nil)
	verifier, err := nizk.NewVerifier(sessionId, verifierTranscript)
	require.NoError(t, err)
	require.NotNil(t, verifier)

	rootBig, err := crand.Int(prng, nBig)
	require.NoError(t, err)
	root := new(saferith.Nat).SetBig(rootBig, 2048)

	witness := nthroot.Witness(root)
	statement := nthroot.Statement(new(saferith.Nat).Exp(witness, n, saferith.ModulusFromNat(nn)))

	proof, err := prover.Prove(statement, witness)
	require.NoError(t, err)
	theProof, ok := proof.(*fischlin.Proof[nthroot.Commitment, nthroot.Response])
	require.True(t, ok)

	err = verifier.Verify(statement, theProof)
	require.NoError(t, err)

	proverBytes, err := proverTranscript.ExtractBytes("Bytes", 32)
	require.NoError(t, err)
	verifierBytes, err := verifierTranscript.ExtractBytes("Bytes", 32)
	require.NoError(t, err)

	require.True(t, bytes.Equal(proverBytes, verifierBytes))

}
