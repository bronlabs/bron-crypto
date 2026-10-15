package compiler_test

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fischlin"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/randfischlin"
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

func TestVerifierRejectsMalformedProof(t *testing.T) {
	t.Parallel()

	for _, compilerName := range []compiler.Name{fiatshamir.Name, fischlin.Name, randfischlin.Name} {
		t.Run(string(compilerName), func(t *testing.T) {
			t.Parallel()

			prng := pcg.NewRandomised()
			curve := k256.NewCurve()
			protocol, err := schnorr.NewProtocol(curve.Generator(), prng)
			require.NoError(t, err)
			nizk, err := compiler.Compile(compilerName, protocol, prng)
			require.NoError(t, err)

			quorum := hashset.NewComparable[sharing.ID](1, 2).Freeze()
			contexts := session_testutils.MakeRandomContexts(t, quorum, prng)
			prover, err := nizk.NewProver(contexts[1])
			require.NoError(t, err)
			witnessValue, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			statement := schnorr.NewStatement(curve.ScalarBaseMul(witnessValue))
			proof, err := prover.Prove(statement, schnorr.NewWitness(witnessValue))
			require.NoError(t, err)

			proofFields := []string{"a", "e", "z"}
			if compilerName == fiatshamir.Name {
				proofFields = []string{"A", "E", "Z"}
			}
			malformedProofs := map[string]compiler.NIZKPoKProof{
				"null":      {0xf6},
				"undefined": {0xf7},
			}
			for _, field := range proofFields {
				malformedProofs[field+"/null"] = replaceProofFieldElement(t, proof, field, cbor.RawMessage{0xf6})
				malformedProofs[field+"/empty map"] = replaceProofFieldElement(t, proof, field, cbor.RawMessage{0xa0})
			}

			for name, malformedProof := range malformedProofs {
				t.Run(name, func(t *testing.T) {
					t.Parallel()

					verifier, err := nizk.NewVerifier(contexts[2].Clone())
					require.NoError(t, err)

					err = verifier.Verify(statement, malformedProof)
					require.True(t, errs.Is(err, proofs.ErrInvalidArgument), "malformed proof returned an unexpected error: %+v", err)

					// Deserialisation must reject malformed data before the
					// verifier transcript is changed.
					require.NoError(t, verifier.Verify(statement, proof))
				})
			}
		})
	}
}

func replaceProofFieldElement(t *testing.T, proof compiler.NIZKPoKProof, field string, replacement cbor.RawMessage) compiler.NIZKPoKProof {
	t.Helper()

	fields, err := serde.UnmarshalCBOR[map[string]cbor.RawMessage](proof)
	require.NoError(t, err)
	original, ok := fields[field]
	require.True(t, ok)
	if field == "A" || field == "E" || field == "Z" {
		fields[field] = replacement
	} else {
		elements, err := serde.UnmarshalCBOR[[]cbor.RawMessage](original)
		require.NoError(t, err)
		require.NotEmpty(t, elements)
		elements[0] = replacement
		fields[field], err = serde.MarshalCBOR(elements)
		require.NoError(t, err)
	}
	tampered, err := serde.MarshalCBOR(fields)
	require.NoError(t, err)
	return tampered
}

func testUsagePattern(t *testing.T, compilerName compiler.Name) {
	t.Helper()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()

	// Setup: create sigma protocol, statement, and witness
	sigmaProtocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(t, err)

	witnessValue, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	witness := schnorr.NewWitness(witnessValue)
	statementValue := curve.ScalarBaseMul(witnessValue)
	statement := schnorr.NewStatement(statementValue)

	// nizk, err := compiler.Compile(fiatshamir.Name, sigmaProtocol, prng)
	nizk, err := compiler.Compile(compilerName, sigmaProtocol, prng)
	require.NoError(t, err, "Compile should succeed for %s", compilerName)

	const proverId = 1
	const verifierId = 2
	quorum := hashset.NewComparable[sharing.ID](proverId, verifierId).Freeze()
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)

	prover, err := nizk.NewProver(ctxs[proverId])
	require.NoError(t, err, "NewProver should succeed for %s", compilerName)

	verifier, err := nizk.NewVerifier(ctxs[verifierId])
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

	prng := pcg.NewRandomised()
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
