package fischlin_test

import (
	"bytes"
	crand "crypto/rand"
	"strconv"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/modular"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dleq/chaum"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/batch_schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/nthroots"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fischlin"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler_utils"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

var supportedCurve = []curves.Curve{
	k256.NewCurve(),
	p256.NewCurve(),
	edwards25519.NewCurve(),
	pasta.NewPallasCurve(),
	pasta.NewVestaCurve(),
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

			nizk, err := compilerUtils.MakeNonInteractive(fischlin.Name, schnorrProtocol, prng)
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

func Test_HappyPathWithBatchSchnorr(t *testing.T) {
	t.Parallel()

	n := 16
	for i, c := range supportedCurve {
		i := i
		curve := c
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			prng := crand.Reader
			sessionId := []byte("TestSessionId" + strconv.Itoa(i))

			schnorrProtocol, err := batch_schnorr.NewSigmaProtocol(uint(n), curve.Generator(), prng)
			require.NoError(t, err)

			nizk, err := compilerUtils.MakeNonInteractive(fischlin.Name, schnorrProtocol, prng)
			require.NoError(t, err)

			proverTranscript := hagrid.NewTranscript("Test"+strconv.Itoa(i), nil)
			prover, err := nizk.NewProver(sessionId, proverTranscript)
			require.NoError(t, err)
			require.NotNil(t, prover)

			verifierTranscript := hagrid.NewTranscript("Test"+strconv.Itoa(i), nil)
			verifier, err := nizk.NewVerifier(sessionId, verifierTranscript)
			require.NoError(t, err)
			require.NotNil(t, verifier)

			witness := make([]curves.Scalar, n)
			for k := range witness {
				witness[k], err = curve.ScalarField().Random(prng)
				require.NoError(t, err)
			}

			statement := make([]curves.Point, n)
			for k, w := range witness {
				statement[k] = curve.ScalarBaseMult(w)
			}

			proof, err := prover.Prove(statement, witness)
			require.NoError(t, err)
			theProof, ok := proof.(*fischlin.Proof[batch_schnorr.Commitment, batch_schnorr.Response])
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

			nizk, err := compilerUtils.MakeNonInteractive(fischlin.Name, chaumPedersenProtocol, prng)
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
				X1: g1.ScalarMul(witness),
				X2: g2.ScalarMul(witness),
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

	n, err := modular.NewFastModulus(new(saferith.Nat).SetBig(nBig, 1024))
	require.NoError(t, err)
	nn := saferith.ModulusFromNat(new(saferith.Nat).Mul(n.Modulus().Nat(), n.Modulus().Nat(), -1))

	nthRootProtocol, err := nthroots.NewSigmaProtocol(n, 1, prng)
	require.NoError(t, err)

	nizk, err := compilerUtils.MakeNonInteractive(fischlin.Name, nthRootProtocol, prng)
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

	witness := nthroots.Witness([]*saferith.Nat{root})
	statement := nthroots.Statement([]*saferith.Nat{new(saferith.Nat).Exp(root, n.Modulus().Nat(), nn)})

	proof, err := prover.Prove(statement, witness)
	require.NoError(t, err)
	theProof, ok := proof.(*fischlin.Proof[nthroots.Commitment, nthroots.Response])
	require.True(t, ok)

	err = verifier.Verify(statement, theProof)
	require.NoError(t, err)

	proverBytes, err := proverTranscript.ExtractBytes("Bytes", 32)
	require.NoError(t, err)
	verifierBytes, err := verifierTranscript.ExtractBytes("Bytes", 32)
	require.NoError(t, err)

	require.True(t, bytes.Equal(proverBytes, verifierBytes))

}
