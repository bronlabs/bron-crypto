package zkmodule_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir/zkmodule"
)

const iters = 16

const (
	proverID   = 1
	verifierID = 2
)

// makeContexts returns two session contexts that share a common seed, so their
// transcripts start in identical states. This is the setting the module assumes:
// prover and verifier derive the same Fiat-Shamir challenge only because they
// absorb the same prefix into the same initial transcript.
func makeContexts(tb testing.TB, prng io.Reader) (proverCtx, verifierCtx *session.Context) {
	tb.Helper()
	quorum := hashset.NewComparable[sharing.ID](proverID, verifierID).Freeze()
	ctxs := session_testutils.MakeRandomContexts(tb, quorum, prng)
	return ctxs[proverID], ctxs[verifierID]
}

// TestZKModule_HappyPath exercises Commit -> Prove -> Verify on a real Schnorr
// sigma protocol across every supported group, and checks that the prover's and
// verifier's transcripts end identical (the response was absorbed on both sides).
func TestZKModule_HappyPath(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		for range iters {
			testHappyPath(t, k256.NewCurve())
		}
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		for range iters {
			testHappyPath(t, p256.NewCurve())
		}
	})
	t.Run("edwards25519", func(t *testing.T) {
		t.Parallel()
		for range iters {
			testHappyPath(t, edwards25519.NewPrimeSubGroup())
		}
	})
	t.Run("curve25519", func(t *testing.T) {
		t.Parallel()
		for range iters {
			testHappyPath(t, curve25519.NewPrimeSubGroup())
		}
	})
	t.Run("pallas", func(t *testing.T) {
		t.Parallel()
		for range iters {
			testHappyPath(t, pasta.NewPallasCurve())
		}
	})
	t.Run("vesta", func(t *testing.T) {
		t.Parallel()
		for range iters {
			testHappyPath(t, pasta.NewVestaCurve())
		}
	})
	t.Run("BLS12-381 G1", func(t *testing.T) {
		t.Parallel()
		for range iters {
			testHappyPath(t, bls12381.NewG1())
		}
	})
	t.Run("BLS12-381 G2", func(t *testing.T) {
		t.Parallel()
		for range iters {
			testHappyPath(t, bls12381.NewG2())
		}
	})
}

func testHappyPath[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](tb testing.TB, group algebra.PrimeGroup[G, S]) {
	tb.Helper()

	prng := pcg.NewRandomised()
	g := group.Generator()
	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())

	witnessValue, err := field.Random(prng)
	require.NoError(tb, err)
	witness := schnorr.NewWitness(witnessValue)
	statement := schnorr.NewStatement(g.ScalarOp(witnessValue))

	protocol, err := schnorr.NewProtocol(g, prng)
	require.NoError(tb, err)

	proverCtx, verifierCtx := makeContexts(tb, prng)

	commitment, state, err := zkmodule.Commit(protocol, statement, witness)
	require.NoError(tb, err)

	proof, err := zkmodule.Prove(proverCtx, protocol, statement, witness, commitment, state)
	require.NoError(tb, err)
	require.NotNil(tb, proof)

	// The recorded challenge is sized to the protocol's challenge length.
	require.Len(tb, proof.Challenge(), protocol.GetChallengeBytesLength())
	// The commitment carried in the proof is the one Commit produced.
	require.Equal(tb, commitment.Bytes(), proof.Commitment().Bytes())

	require.NoError(tb, zkmodule.Verify(verifierCtx, protocol, statement, proof))

	// After a full exchange the two transcripts must be byte-identical.
	proverTail, err := proverCtx.Transcript().ExtractBytes("tail", 32)
	require.NoError(tb, err)
	verifierTail, err := verifierCtx.Transcript().ExtractBytes("tail", 32)
	require.NoError(tb, err)
	require.True(tb, bytes.Equal(proverTail, verifierTail))
}

// TestZKModule_WrongWitness proves against a witness that does not open the
// statement. The challenge still matches (same statement/commitment absorbed),
// so verification fails at the sigma relation check, not the challenge check.
func TestZKModule_WrongWitness(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()

	protocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(t, err)

	witnessValue, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	statement := schnorr.NewStatement(curve.ScalarBaseMul(witnessValue))

	wrongWitnessValue, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	wrongWitness := schnorr.NewWitness(wrongWitnessValue)

	proverCtx, verifierCtx := makeContexts(t, prng)

	commitment, state, err := zkmodule.Commit(protocol, statement, wrongWitness)
	require.NoError(t, err)
	proof, err := zkmodule.Prove(proverCtx, protocol, statement, wrongWitness, commitment, state)
	require.NoError(t, err)

	err = zkmodule.Verify(verifierCtx, protocol, statement, proof)
	require.Error(t, err)
	require.True(t, errs.Is(err, proofs.ErrVerificationFailed))
}

// TestZKModule_WrongStatement verifies a valid proof against a different
// statement. The verifier absorbs the wrong statement, re-derives a different
// challenge e', and rejects on the challenge-binding check.
func TestZKModule_WrongStatement(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()

	protocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(t, err)

	witnessValue, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	witness := schnorr.NewWitness(witnessValue)
	statement := schnorr.NewStatement(curve.ScalarBaseMul(witnessValue))

	otherValue, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	otherStatement := schnorr.NewStatement(curve.ScalarBaseMul(otherValue))

	proverCtx, verifierCtx := makeContexts(t, prng)

	commitment, state, err := zkmodule.Commit(protocol, statement, witness)
	require.NoError(t, err)
	proof, err := zkmodule.Prove(proverCtx, protocol, statement, witness, commitment, state)
	require.NoError(t, err)

	err = zkmodule.Verify(verifierCtx, protocol, otherStatement, proof)
	require.Error(t, err)
	require.True(t, errs.Is(err, proofs.ErrVerificationFailed))
}

// TestZKModule_MarshalRoundTrip checks that a proof survives a CBOR round trip
// with its accessors intact and that the decoded proof still verifies.
func TestZKModule_MarshalRoundTrip(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()

	protocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(t, err)

	witnessValue, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	witness := schnorr.NewWitness(witnessValue)
	statement := schnorr.NewStatement(curve.ScalarBaseMul(witnessValue))

	proverCtx, verifierCtx := makeContexts(t, prng)

	commitment, state, err := zkmodule.Commit(protocol, statement, witness)
	require.NoError(t, err)
	proof, err := zkmodule.Prove(proverCtx, protocol, statement, witness, commitment, state)
	require.NoError(t, err)

	data, err := serde.MarshalCBOR(proof)
	require.NoError(t, err)

	decoded, err := serde.UnmarshalCBOR[*zkmodule.Proof[*schnorr.Commitment[*k256.Point, *k256.Scalar], *schnorr.Response[*k256.Scalar]]](data)
	require.NoError(t, err)

	require.Equal(t, proof.Commitment().Bytes(), decoded.Commitment().Bytes())
	require.Equal(t, proof.Challenge(), decoded.Challenge())
	require.Equal(t, proof.Response().Bytes(), decoded.Response().Bytes())

	require.NoError(t, zkmodule.Verify(verifierCtx, protocol, statement, decoded))
}

func TestZKModuleProofUnmarshalRejectsNull(t *testing.T) {
	t.Parallel()

	for name, data := range map[string][]byte{
		"null":      {0xf6},
		"undefined": {0xf7},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var proof zkmodule.Proof[
				*schnorr.Commitment[*k256.Point, *k256.Scalar],
				*schnorr.Response[*k256.Scalar],
			]
			err := proof.UnmarshalCBOR(data)
			require.True(t, errs.Is(err, proofs.ErrInvalidArgument), "unexpected error: %+v", err)
		})
	}
}

// TestZKModule_TamperedProofBytes flips a byte in a serialised proof. Decoding
// must either fail outright or yield a proof that no longer verifies; a
// tampered proof must never be accepted.
func TestZKModule_TamperedProofBytes(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()

	protocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(t, err)

	witnessValue, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	witness := schnorr.NewWitness(witnessValue)
	statement := schnorr.NewStatement(curve.ScalarBaseMul(witnessValue))

	proverCtx, verifierCtx := makeContexts(t, prng)

	commitment, state, err := zkmodule.Commit(protocol, statement, witness)
	require.NoError(t, err)
	proof, err := zkmodule.Prove(proverCtx, protocol, statement, witness, commitment, state)
	require.NoError(t, err)

	data, err := serde.MarshalCBOR(proof)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Flip a byte near the end, which lands in the response/challenge region.
	tampered := bytes.Clone(data)
	tampered[len(tampered)-1] ^= 0xFF

	decoded, err := serde.UnmarshalCBOR[*zkmodule.Proof[*schnorr.Commitment[*k256.Point, *k256.Scalar], *schnorr.Response[*k256.Scalar]]](tampered)
	if err != nil {
		return // decoding rejected the tampering — acceptable.
	}
	require.Error(t, zkmodule.Verify(verifierCtx, protocol, statement, decoded))
}

// TestZKModule_NilArguments asserts the guard clauses of each entry point report
// proofs.ErrInvalidArgument rather than panicking.
func TestZKModule_NilArguments(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()

	protocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(t, err)

	witnessValue, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	witness := schnorr.NewWitness(witnessValue)
	statement := schnorr.NewStatement(curve.ScalarBaseMul(witnessValue))

	proverCtx, verifierCtx := makeContexts(t, prng)

	commitment, state, err := zkmodule.Commit(protocol, statement, witness)
	require.NoError(t, err)
	proof, err := zkmodule.Prove(proverCtx, protocol, statement, witness, commitment, state)
	require.NoError(t, err)

	t.Run("Commit nil protocol", func(t *testing.T) {
		t.Parallel()
		_, _, err := zkmodule.Commit[
			*schnorr.Statement[*k256.Point, *k256.Scalar],
			*schnorr.Witness[*k256.Scalar],
			*schnorr.Commitment[*k256.Point, *k256.Scalar],
			*schnorr.State[*k256.Scalar],
			*schnorr.Response[*k256.Scalar],
		](nil, statement, witness)
		require.True(t, errs.Is(err, proofs.ErrInvalidArgument))
	})

	t.Run("Prove nil ctx", func(t *testing.T) {
		t.Parallel()
		_, err := zkmodule.Prove(nil, protocol, statement, witness, commitment, state)
		require.True(t, errs.Is(err, proofs.ErrInvalidArgument))
	})

	t.Run("Verify nil ctx", func(t *testing.T) {
		t.Parallel()
		err := zkmodule.Verify(nil, protocol, statement, proof)
		require.True(t, errs.Is(err, proofs.ErrInvalidArgument))
	})

	t.Run("Verify nil proof", func(t *testing.T) {
		t.Parallel()
		err := zkmodule.Verify(verifierCtx, protocol, statement, nil)
		require.True(t, errs.Is(err, proofs.ErrInvalidArgument))
	})
}

// TestZKModule_CrossCurveCompiles is a tiny compile/run guard that the generic
// API works with a non-k256 instantiation end-to-end.
func TestZKModule_CrossCurveCompiles(t *testing.T) {
	t.Parallel()
	testHappyPath(t, p256.NewCurve())
}
