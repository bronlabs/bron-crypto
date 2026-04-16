package elog_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/commitments/indcpacom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
	"github.com/bronlabs/bron-crypto/pkg/proofs/elog"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		testHappyPath(t, k256.NewCurve())
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		testHappyPath(t, p256.NewCurve())
	})
}

func Test_ElGamalIndCPACommitment(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		testElGamalCommitment(t, k256.NewCurve())
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		testElGamalCommitment(t, p256.NewCurve())
	})
}

func Test_Simulator(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		testSimulator(t, k256.NewCurve())
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		testSimulator(t, p256.NewCurve())
	})
}

func Test_Extractor(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		testExtractor(t, k256.NewCurve())
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		testExtractor(t, p256.NewCurve())
	})
}

func Test_WrongWitness(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()
	sf := k256.NewScalarField()

	pk, h := mustSetup(t, curve, prng)
	g := curve.Generator()

	lambda, err := sf.Random(prng)
	require.NoError(t, err)
	y, err := sf.Random(prng)
	require.NoError(t, err)

	bigL := g.ScalarMul(lambda)
	bigM := g.ScalarMul(y).Add(pk.Value().ScalarMul(lambda))
	bigY := h.ScalarMul(y)

	protocol, err := elog.NewProtocol(curve, pk, h, prng)
	require.NoError(t, err)

	statement, err := elog.NewStatement(bigL, bigM, bigY)
	require.NoError(t, err)

	wrongLambda, err := sf.Random(prng)
	require.NoError(t, err)
	wrongY, err := sf.Random(prng)
	require.NoError(t, err)
	wrongNonce, err := elgamal.NewNonce(wrongLambda)
	require.NoError(t, err)
	wrongWitness, err := elog.NewWitness(wrongNonce, wrongY)
	require.NoError(t, err)

	commitment, state, err := protocol.ComputeProverCommitment(statement, wrongWitness)
	require.NoError(t, err)

	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge)
	require.NoError(t, err)

	response, err := protocol.ComputeProverResponse(statement, wrongWitness, commitment, state, challenge)
	require.NoError(t, err)

	err = protocol.Verify(statement, commitment, challenge, response)
	require.Error(t, err)
}

// --- Generic helpers ---

// mustSetup returns an ElGamal public key and a second independent generator h.
func mustSetup[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S], prng io.Reader,
) (*elgamal.PublicKey[P, S], P) {
	tb.Helper()
	scheme, err := elgamal.NewScheme(curve)
	require.NoError(tb, err)
	kg, err := scheme.Keygen()
	require.NoError(tb, err)
	_, pk, err := kg.Generate(prng)
	require.NoError(tb, err)
	// h is a second independent generator (e.g. hash-to-curve or random point)
	hPoint, err := curve.Random(prng)
	require.NoError(tb, err)
	return pk, hPoint
}

func testHappyPath[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S],
) {
	tb.Helper()
	prng := pcg.NewRandomised()
	sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](curve.ScalarStructure())

	pk, h := mustSetup(tb, curve, prng)
	g := curve.Generator()

	lambda, err := sf.Random(prng)
	require.NoError(tb, err)
	y, err := sf.Random(prng)
	require.NoError(tb, err)

	// L = g^lambda, M = g^y * X^lambda, Y = h^y
	bigL := g.ScalarMul(lambda)
	bigM := g.ScalarMul(y).Add(pk.Value().ScalarMul(lambda))
	bigY := h.ScalarMul(y)

	protocol, err := elog.NewProtocol(curve, pk, h, prng)
	require.NoError(tb, err)

	statement, err := elog.NewStatement(bigL, bigM, bigY)
	require.NoError(tb, err)
	nonce, err := elgamal.NewNonce(lambda)
	require.NoError(tb, err)
	witness, err := elog.NewWitness(nonce, y)
	require.NoError(tb, err)

	err = protocol.ValidateStatement(statement, witness)
	require.NoError(tb, err)

	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(tb, err)

	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge)
	require.NoError(tb, err)

	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(tb, err)

	err = protocol.Verify(statement, commitment, challenge, response)
	require.NoError(tb, err)
}

// testElGamalCommitment tests the full path: create an ElGamal commitment via
// indcpacom, extract the ciphertext components, and prove knowledge of
// (lambda, y) such that (L, M) encrypts g^y and Y = h^y.
func testElGamalCommitment[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S],
) {
	tb.Helper()
	prng := pcg.NewRandomised()
	sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](curve.ScalarStructure())

	// Setup ElGamal encryption and indcpacom commitment scheme.
	// X = ElGamal public key, h = independent second generator.
	encScheme, err := elgamal.NewScheme(curve)
	require.NoError(tb, err)
	kg, err := encScheme.Keygen()
	require.NoError(tb, err)
	_, pk, err := kg.Generate(prng)
	require.NoError(tb, err)

	h, err := curve.Random(prng)
	require.NoError(tb, err)

	comKey, err := indcpacom.NewKey(pk)
	require.NoError(tb, err)
	comScheme, err := indcpacom.NewScheme(encScheme, comKey)
	require.NoError(tb, err)
	committer, err := comScheme.Committer()
	require.NoError(tb, err)

	// Secret y, plaintext is g^y
	g := curve.Generator()
	y, err := sf.Random(prng)
	require.NoError(tb, err)
	gY := g.ScalarMul(y)

	pt, err := elgamal.NewPlaintext(gY)
	require.NoError(tb, err)
	msg, err := indcpacom.NewMessage(pt)
	require.NoError(tb, err)

	com, wit, err := committer.Commit(msg, prng)
	require.NoError(tb, err)

	// Extract ciphertext components: (L, M) = (g^lambda, g^y * X^lambda)
	ct := com.Value()
	components := ct.Value().Components()
	bigL := components[0]
	bigM := components[1]

	// lambda is the ElGamal nonce (wit.Value() is already *elgamal.Nonce)
	nonce := wit.Value()

	// Y = h^y
	bigY := h.ScalarMul(y)

	// Prove knowledge of (lambda, y)
	protocol, err := elog.NewProtocol(curve, pk, h, prng)
	require.NoError(tb, err)

	statement, err := elog.NewStatement(bigL, bigM, bigY)
	require.NoError(tb, err)
	witness, err := elog.NewWitness(nonce, y)
	require.NoError(tb, err)

	err = protocol.ValidateStatement(statement, witness)
	require.NoError(tb, err)

	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(tb, err)

	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge)
	require.NoError(tb, err)

	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(tb, err)

	err = protocol.Verify(statement, commitment, challenge, response)
	require.NoError(tb, err)
}

func testSimulator[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S],
) {
	tb.Helper()
	prng := pcg.NewRandomised()

	pk, h := mustSetup(tb, curve, prng)
	protocol, err := elog.NewProtocol(curve, pk, h, prng)
	require.NoError(tb, err)

	// Random statement (simulator doesn't need a valid witness)
	r1, err := curve.Random(prng)
	require.NoError(tb, err)
	r2, err := curve.Random(prng)
	require.NoError(tb, err)
	r3, err := curve.Random(prng)
	require.NoError(tb, err)
	statement, err := elog.NewStatement(r1, r2, r3)
	require.NoError(tb, err)

	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge)
	require.NoError(tb, err)

	commitment, response, err := protocol.RunSimulator(statement, challenge)
	require.NoError(tb, err)

	err = protocol.Verify(statement, commitment, challenge, response)
	require.NoError(tb, err)
}

func testExtractor[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S],
) {
	tb.Helper()
	prng := pcg.NewRandomised()
	sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](curve.ScalarStructure())

	pk, h := mustSetup(tb, curve, prng)
	g := curve.Generator()

	lambda, err := sf.Random(prng)
	require.NoError(tb, err)
	y, err := sf.Random(prng)
	require.NoError(tb, err)

	bigL := g.ScalarMul(lambda)
	bigM := g.ScalarMul(y).Add(pk.Value().ScalarMul(lambda))
	bigY := h.ScalarMul(y)

	protocol, err := elog.NewProtocol(curve, pk, h, prng)
	require.NoError(tb, err)

	statement, err := elog.NewStatement(bigL, bigM, bigY)
	require.NoError(tb, err)
	nonce, err := elgamal.NewNonce(lambda)
	require.NoError(tb, err)
	witness, err := elog.NewWitness(nonce, y)
	require.NoError(tb, err)

	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(tb, err)

	challenge1 := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge1)
	require.NoError(tb, err)
	challenge2 := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge2)
	require.NoError(tb, err)

	response1, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge1)
	require.NoError(tb, err)
	response2, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge2)
	require.NoError(tb, err)

	ei := []sigma.ChallengeBytes{challenge1, challenge2}
	zi := []*elog.Response[S]{response1, response2}

	wExtracted, err := protocol.Extract(statement, commitment, ei, zi)
	require.NoError(tb, err)
	require.True(tb, wExtracted.Value().Equal(witness.Value()))
}
