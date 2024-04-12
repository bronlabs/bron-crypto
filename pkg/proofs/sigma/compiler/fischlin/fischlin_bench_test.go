package fischlin_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dleq/chaum"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/nthroot"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/fischlin"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

func Benchmark_Schnorr(b *testing.B) {
	curve := k256.NewCurve()
	prng := crand.Reader
	sessionId := []byte("TestSessionId")

	schnorrProtocol, err := schnorr.NewSigmaProtocol(curve.Generator(), prng)
	require.NoError(b, err)

	for rho := uint64(8); rho <= 64; rho++ {
		nizk, err := fischlin.NewCompiler(schnorrProtocol, rho, prng)
		require.NoError(b, err)

		proverTranscript := hagrid.NewTranscript("Test", nil)
		prover, err := nizk.NewProver(sessionId, proverTranscript)
		require.NoError(b, err)
		require.NotNil(b, prover)

		verifierTranscript := hagrid.NewTranscript("Test", nil)
		verifier, err := nizk.NewVerifier(sessionId, verifierTranscript)
		require.NoError(b, err)
		require.NotNil(b, verifier)

		witness, err := curve.ScalarField().Random(prng)
		require.NoError(b, err)
		statement := curve.ScalarBaseMult(witness)

		b.ResetTimer()
		b.Run(fmt.Sprintf("%d", rho), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := prover.Prove(statement, witness)
				require.NoError(b, err)
			}
		})
	}
}

func Benchmark_ChaumPedersen(b *testing.B) {
	curve := k256.NewCurve()
	prng := crand.Reader
	sessionId := []byte("TestSessionId")

	g1, err := curve.Random(prng)
	require.NoError(b, err)
	g2, err := curve.Random(prng)
	require.NoError(b, err)

	chaumPedersenProtocol, err := chaum.NewSigmaProtocol(g1, g2, prng)
	require.NoError(b, err)

	for rho := uint64(8); rho <= 64; rho++ {
		nizk, err := fischlin.NewCompiler(chaumPedersenProtocol, rho, prng)
		require.NoError(b, err)

		proverTranscript := hagrid.NewTranscript("Test", nil)
		prover, err := nizk.NewProver(sessionId, proverTranscript)
		require.NoError(b, err)
		require.NotNil(b, prover)

		verifierTranscript := hagrid.NewTranscript("Test", nil)
		verifier, err := nizk.NewVerifier(sessionId, verifierTranscript)
		require.NoError(b, err)
		require.NotNil(b, verifier)

		scalar, err := curve.ScalarField().Random(prng)
		require.NoError(b, err)

		witness := chaum.Witness(scalar)
		statement := &chaum.Statement{
			X1: g1.Mul(witness),
			X2: g2.Mul(witness),
		}

		b.Run(fmt.Sprintf("rho: %d", rho), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := prover.Prove(statement, witness)
				require.NoError(b, err)
			}
		})
	}
}

func Benchmark_NthRoot(b *testing.B) {
	prng := crand.Reader
	sessionId := []byte("TestSessionId")

	nBig, err := crand.Prime(prng, 512)
	require.NoError(b, err)
	n := new(saferith.Nat).SetBig(nBig, 512)
	nn := new(saferith.Nat).Mul(n, n, 1024)

	nthRootProtocol, err := nthroot.NewSigmaProtocol(n, prng)
	require.NoError(b, err)

	for rho := uint64(16); rho <= 64; rho++ {
		nizk, err := fischlin.NewCompiler(nthRootProtocol, rho, prng)
		require.NoError(b, err)

		proverTranscript := hagrid.NewTranscript("Test", nil)
		prover, err := nizk.NewProver(sessionId, proverTranscript)
		require.NoError(b, err)
		require.NotNil(b, prover)

		verifierTranscript := hagrid.NewTranscript("Test", nil)
		verifier, err := nizk.NewVerifier(sessionId, verifierTranscript)
		require.NoError(b, err)
		require.NotNil(b, verifier)

		rootBig, err := crand.Int(prng, nBig)
		require.NoError(b, err)
		root := new(saferith.Nat).SetBig(rootBig, 2048)

		witness := nthroot.Witness(root)
		statement := nthroot.Statement(new(saferith.Nat).Exp(witness, n, saferith.ModulusFromNat(nn)))

		b.Run(fmt.Sprintf("rho: %d", rho), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := prover.Prove(statement, witness)
				require.NoError(b, err)
			}
		})
	}
}
