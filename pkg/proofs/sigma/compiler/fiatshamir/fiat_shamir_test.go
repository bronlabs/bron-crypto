package fiatshamir_test

import (
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"
)

const iters = 128

func TestSchnorrFiatShamir(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		for range iters {
			testSchnorrFiatShamir(t, k256.NewCurve())
		}
	})
	t.Run("p256", func(t *testing.T) {
		for range iters {
			testSchnorrFiatShamir(t, p256.NewCurve())
		}
	})
	t.Run("edwards25519", func(t *testing.T) {
		for range iters {
			testSchnorrFiatShamir(t, edwards25519.NewPrimeSubGroup())
		}
	})
	t.Run("curve25519", func(t *testing.T) {
		for range iters {
			testSchnorrFiatShamir(t, curve25519.NewPrimeSubGroup())
		}
	})
	t.Run("pallas", func(t *testing.T) {
		for range iters {
			testSchnorrFiatShamir(t, pasta.NewPallasCurve())
		}
	})
	t.Run("vesta", func(t *testing.T) {
		for range iters {
			testSchnorrFiatShamir(t, pasta.NewVestaCurve())
		}
	})
	t.Run("BLS12-381 G1", func(t *testing.T) {
		for range iters {
			testSchnorrFiatShamir(t, bls12381.NewG1())
		}
	})
	t.Run("BLS12-381 G2", func(t *testing.T) {
		for range iters {
			testSchnorrFiatShamir(t, bls12381.NewG2())
		}
	})
}

func testSchnorrFiatShamir[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](t *testing.T, group algebra.PrimeGroup[G, S]) {
	t.Helper()

	prng := crand.Reader
	var sid network.SID
	_, err := io.ReadFull(prng, sid[:])
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
