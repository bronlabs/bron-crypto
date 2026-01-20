package compiler_test

import (
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fischlin"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/randfischlin"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func TestCompile_UsagePattern(t *testing.T) {
	t.Parallel()

	compilerNames := []compiler.Name{
		fiatshamir.Name,
		fischlin.Name,
		randfischlin.Name,
	}

	for _, compilerName := range compilerNames {
		t.Run(string(compilerName), func(t *testing.T) {
			t.Parallel()
			testUsagePattern(t, compilerName)
		})
	}
}

func testUsagePattern(t *testing.T, compilerName compiler.Name) {
	t.Helper()

	prng := crand.Reader
	curve := k256.NewCurve()

	// Setup: create sigma protocol, statement, and witness
	sigmaProtocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(t, err)

	witnessValue, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	witness := schnorr.NewWitness(witnessValue)
	statementValue := curve.ScalarBaseMul(witnessValue)
	statement := schnorr.NewStatement(statementValue)

	var sessionID network.SID
	_, err = io.ReadFull(prng, sessionID[:])
	require.NoError(t, err)

	// nizk, err := compiler.Compile(fiatshamir.Name, sigmaProtocol, prng)
	nizk, err := compiler.Compile(compilerName, sigmaProtocol, prng)
	require.NoError(t, err, "Compile should succeed for %s", compilerName)

	// prover, _ := nizk.NewProver(sessionID, transcript)
	proverTranscript := hagrid.NewTranscript("test")
	prover, err := nizk.NewProver(sessionID, proverTranscript)
	require.NoError(t, err, "NewProver should succeed for %s", compilerName)

	// verifier, _ := nizk.NewVerifier(sessionID, transcript)
	verifierTranscript := hagrid.NewTranscript("test")
	verifier, err := nizk.NewVerifier(sessionID, verifierTranscript)
	require.NoError(t, err, "NewVerifier should succeed for %s", compilerName)

	// proof, _ := prover.Prove(statement, witness)
	proof, err := prover.Prove(statement, witness)
	require.NoError(t, err, "Prove should succeed for %s", compilerName)

	// err = verifier.Verify(statement, proof)
	err = verifier.Verify(statement, proof)
	require.NoError(t, err, "Verify should succeed for %s", compilerName)
}

func TestCompile_UnsupportedCompiler(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	curve := k256.NewCurve()

	sigmaProtocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(t, err)

	_, err = compiler.Compile("unknown", sigmaProtocol, prng)
	require.Error(t, err)
}

func TestIsSupported(t *testing.T) {
	t.Parallel()

	require.True(t, compiler.IsSupported(fiatshamir.Name))
	require.True(t, compiler.IsSupported(fischlin.Name))
	require.True(t, compiler.IsSupported(randfischlin.Name))
	require.False(t, compiler.IsSupported("unknown"))
}
