package fiatshamir_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

const iters = 32

func TestFiatShamir_HappyPath(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		for range iters {
			testSchnorrFiatShamir(t, k256.NewCurve())
		}
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		for range iters {
			testSchnorrFiatShamir(t, p256.NewCurve())
		}
	})
	t.Run("edwards25519", func(t *testing.T) {
		t.Parallel()
		for range iters {
			testSchnorrFiatShamir(t, edwards25519.NewPrimeSubGroup())
		}
	})
	t.Run("curve25519", func(t *testing.T) {
		t.Parallel()
		for range iters {
			testSchnorrFiatShamir(t, curve25519.NewPrimeSubGroup())
		}
	})
	t.Run("pallas", func(t *testing.T) {
		t.Parallel()
		for range iters {
			testSchnorrFiatShamir(t, pasta.NewPallasCurve())
		}
	})
	t.Run("vesta", func(t *testing.T) {
		t.Parallel()
		for range iters {
			testSchnorrFiatShamir(t, pasta.NewVestaCurve())
		}
	})
	t.Run("BLS12-381 G1", func(t *testing.T) {
		t.Parallel()
		for range iters {
			testSchnorrFiatShamir(t, bls12381.NewG1())
		}
	})
	t.Run("BLS12-381 G2", func(t *testing.T) {
		t.Parallel()
		for range iters {
			testSchnorrFiatShamir(t, bls12381.NewG2())
		}
	})
}

func testSchnorrFiatShamir[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](t *testing.T, group algebra.PrimeGroup[G, S]) {
	t.Helper()

	prng := pcg.NewRandomised()
	var sid network.SID
	_, err := io.ReadFull(prng, sid[:])
	require.NoError(t, err)
	g := group.Generator()
	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
	witnessValue, err := field.Random(prng)
	require.NoError(t, err)
	statementValue := g.ScalarOp(witnessValue)

	scheme, err := schnorr.NewProtocol(g, prng)
	require.NoError(t, err)
	witness := schnorr.NewWitness(witnessValue)
	statement := schnorr.NewStatement(statementValue)

	niScheme, err := fiatshamir.NewCompiler(scheme)
	require.NoError(t, err)
	proverTranscript := hagrid.NewTranscript("test")
	verifierTranscript := proverTranscript.Clone()

	prover, err := niScheme.NewProver(sid, proverTranscript)
	require.NoError(t, err)
	proof, err := prover.Prove(statement, witness)
	require.NoError(t, err)

	verifier, err := niScheme.NewVerifier(sid, verifierTranscript)
	require.NoError(t, err)
	err = verifier.Verify(statement, proof)
	require.NoError(t, err)

	proverTapeData, err := proverTranscript.ExtractBytes("test", base.CollisionResistanceBytesCeil)
	require.NoError(t, err)
	verifierTapeData, err := verifierTranscript.ExtractBytes("test", base.CollisionResistanceBytesCeil)
	require.NoError(t, err)

	require.Equal(t, proverTapeData, verifierTapeData)
}

func TestFiatShamir_WrongWitness(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()

	var sessionID network.SID
	_, err := io.ReadFull(prng, sessionID[:])
	require.NoError(t, err)

	schnorrProtocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(t, err)

	// Create correct witness and statement
	witnessValue, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	statementValue := curve.ScalarBaseMul(witnessValue)
	statement := schnorr.NewStatement(statementValue)

	// Create wrong witness
	wrongWitnessValue, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	wrongWitness := schnorr.NewWitness(wrongWitnessValue)

	niScheme, err := fiatshamir.NewCompiler(schnorrProtocol)
	require.NoError(t, err)

	proverTranscript := hagrid.NewTranscript("test")
	verifierTranscript := proverTranscript.Clone()

	prover, err := niScheme.NewProver(sessionID, proverTranscript)
	require.NoError(t, err)
	proof, err := prover.Prove(statement, wrongWitness)
	require.NoError(t, err)

	verifier, err := niScheme.NewVerifier(sessionID, verifierTranscript)
	require.NoError(t, err)

	// Verification should fail with wrong witness
	err = verifier.Verify(statement, proof)
	require.Error(t, err)
}

func TestFiatShamir_TamperedProof(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()

	var sessionID network.SID
	_, err := io.ReadFull(prng, sessionID[:])
	require.NoError(t, err)

	schnorrProtocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(t, err)

	witnessValue, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	witness := schnorr.NewWitness(witnessValue)
	statementValue := curve.ScalarBaseMul(witnessValue)
	statement := schnorr.NewStatement(statementValue)

	niScheme, err := fiatshamir.NewCompiler(schnorrProtocol)
	require.NoError(t, err)

	proverTranscript := hagrid.NewTranscript("test")
	verifierTranscript := proverTranscript.Clone()

	prover, err := niScheme.NewProver(sessionID, proverTranscript)
	require.NoError(t, err)
	proof, err := prover.Prove(statement, witness)
	require.NoError(t, err)

	// Tamper with the proof
	if len(proof) > 0 {
		proof[0] ^= 0xFF
	}

	verifier, err := niScheme.NewVerifier(sessionID, verifierTranscript)
	require.NoError(t, err)

	// Verification should fail with tampered proof
	err = verifier.Verify(statement, proof)
	require.Error(t, err)
}

func TestFiatShamir_EmptyProof(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()

	var sessionID network.SID
	_, err := io.ReadFull(prng, sessionID[:])
	require.NoError(t, err)

	schnorrProtocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(t, err)

	witnessValue, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	statementValue := curve.ScalarBaseMul(witnessValue)
	statement := schnorr.NewStatement(statementValue)

	niScheme, err := fiatshamir.NewCompiler(schnorrProtocol)
	require.NoError(t, err)

	verifierTranscript := hagrid.NewTranscript("test")
	verifier, err := niScheme.NewVerifier(sessionID, verifierTranscript)
	require.NoError(t, err)

	// Verification should fail with empty proof
	err = verifier.Verify(statement, nil)
	require.Error(t, err)

	err = verifier.Verify(statement, []byte{})
	require.Error(t, err)
}

func TestFiatShamir_WrongSessionID(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()

	var proverSessionID, verifierSessionID network.SID
	_, err := io.ReadFull(prng, proverSessionID[:])
	require.NoError(t, err)
	_, err = io.ReadFull(prng, verifierSessionID[:])
	require.NoError(t, err)

	schnorrProtocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(t, err)

	witnessValue, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	witness := schnorr.NewWitness(witnessValue)
	statementValue := curve.ScalarBaseMul(witnessValue)
	statement := schnorr.NewStatement(statementValue)

	niScheme, err := fiatshamir.NewCompiler(schnorrProtocol)
	require.NoError(t, err)

	proverTranscript := hagrid.NewTranscript("test")
	verifierTranscript := hagrid.NewTranscript("test")

	prover, err := niScheme.NewProver(proverSessionID, proverTranscript)
	require.NoError(t, err)
	proof, err := prover.Prove(statement, witness)
	require.NoError(t, err)

	// Use different session ID for verifier
	verifier, err := niScheme.NewVerifier(verifierSessionID, verifierTranscript)
	require.NoError(t, err)

	// Verification should fail with wrong session ID
	err = verifier.Verify(statement, proof)
	require.Error(t, err)
}

func TestFiatShamir_NilCompilerInput(t *testing.T) {
	t.Parallel()

	_, err := fiatshamir.NewCompiler[
		*schnorr.Statement[*k256.Point, *k256.Scalar],
		*schnorr.Witness[*k256.Scalar],
		*schnorr.Commitment[*k256.Point, *k256.Scalar],
		*schnorr.State[*k256.Scalar],
		*schnorr.Response[*k256.Scalar],
	](nil)
	require.Error(t, err)
}

func TestFiatShamir_TranscriptsMatch(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		testTranscriptsMatch(t, k256.NewCurve())
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		testTranscriptsMatch(t, p256.NewCurve())
	})
}

func testTranscriptsMatch[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](tb testing.TB, curve curves.Curve[P, B, S]) {
	tb.Helper()

	prng := pcg.NewRandomised()
	var sessionID network.SID
	_, err := io.ReadFull(prng, sessionID[:])
	require.NoError(tb, err)

	schnorrProtocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(tb, err)

	witnessValue, err := curve.ScalarField().Random(prng)
	require.NoError(tb, err)
	witness := &schnorr.Witness[S]{W: witnessValue}
	statementValue := curve.ScalarBaseMul(witnessValue)
	statement := &schnorr.Statement[P, S]{X: statementValue}

	niScheme, err := fiatshamir.NewCompiler(schnorrProtocol)
	require.NoError(tb, err)

	proverTranscript := hagrid.NewTranscript("test")
	verifierTranscript := hagrid.NewTranscript("test")

	prover, err := niScheme.NewProver(sessionID, proverTranscript)
	require.NoError(tb, err)
	proof, err := prover.Prove(statement, witness)
	require.NoError(tb, err)

	verifier, err := niScheme.NewVerifier(sessionID, verifierTranscript)
	require.NoError(tb, err)
	err = verifier.Verify(statement, proof)
	require.NoError(tb, err)

	// Verify transcripts match after proof/verify
	proverBytes, err := proverTranscript.ExtractBytes("final", 32)
	require.NoError(tb, err)
	verifierBytes, err := verifierTranscript.ExtractBytes("final", 32)
	require.NoError(tb, err)
	require.True(tb, bytes.Equal(proverBytes, verifierBytes))
}
