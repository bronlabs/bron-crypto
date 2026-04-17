package elog_test

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/commitments/indcpacom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
	schnorrpok "github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/elgamal/elcomop"
	"github.com/bronlabs/bron-crypto/pkg/proofs/elgamal/elog"
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

func Test_WrongWitness(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()
	sf := k256.NewScalarField()

	pk, comKey, committer, h := mustSetup(t, curve, prng)
	g := curve.Generator()

	// Honest (lambda, y) yields a valid statement S.
	lambda, err := sf.Random(prng)
	require.NoError(t, err)
	y, err := sf.Random(prng)
	require.NoError(t, err)
	_, com := mustCommit(t, g, y, lambda, committer)
	bigY := h.ScalarMul(y)
	statement := mustElogStatement(t, com, bigY)

	// Independently-sampled (lambda', y') gives a witness that passes NewWitness
	// (M' = g^y' for its own y') but is inconsistent with the statement above.
	wrongLambda, err := sf.Random(prng)
	require.NoError(t, err)
	wrongY, err := sf.Random(prng)
	require.NoError(t, err)
	wrongWitness, _ := mustElogWitness(t, g, wrongY, wrongLambda, committer)

	protocol, err := elog.NewProtocol(curve, comKey, h, prng)
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

	_ = pk
}

func Test_NewWitness_Mismatch(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()
	sf := k256.NewScalarField()
	g := curve.Generator()

	_, _, committer, _ := mustSetup(t, curve, prng)

	// elcomop witness uses plaintext = g^y1 with nonce lambda.
	y1, err := sf.Random(prng)
	require.NoError(t, err)
	lambda, err := sf.Random(prng)
	require.NoError(t, err)
	elcomopWit, _ := mustCommit(t, g, y1, lambda, committer)

	// schnorr witness uses a different scalar y2 so g^y2 != plaintext.
	y2, err := sf.Random(prng)
	require.NoError(t, err)
	schnorrWit := schnorrpok.NewWitness(y2)

	_, err = elog.NewWitness(elcomopWit, schnorrWit)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Schnorr witness does not match")
}

func Test_NewWitness_Nil(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()
	sf := k256.NewScalarField()
	g := curve.Generator()

	_, _, committer, _ := mustSetup(t, curve, prng)

	y, err := sf.Random(prng)
	require.NoError(t, err)
	lambda, err := sf.Random(prng)
	require.NoError(t, err)
	elcomopWit, _ := mustCommit(t, g, y, lambda, committer)
	schnorrWit := schnorrpok.NewWitness(y)

	_, err = elog.NewWitness[*k256.Point, *k256.Scalar](nil, schnorrWit)
	require.Error(t, err)

	_, err = elog.NewWitness(elcomopWit, nil)
	require.Error(t, err)
}

func Test_NewStatement_Nil(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()
	sf := k256.NewScalarField()
	g := curve.Generator()

	_, _, committer, h := mustSetup(t, curve, prng)

	y, err := sf.Random(prng)
	require.NoError(t, err)
	lambda, err := sf.Random(prng)
	require.NoError(t, err)
	_, com := mustCommit(t, g, y, lambda, committer)
	elcomopStmt, err := elcomop.NewStatement(com)
	require.NoError(t, err)
	schnorrStmt := schnorrpok.NewStatement[*k256.Point, *k256.Scalar](h.ScalarMul(y))

	_, err = elog.NewStatement[*k256.Point, *k256.Scalar](nil, schnorrStmt)
	require.Error(t, err)

	_, err = elog.NewStatement[*k256.Point, *k256.Scalar](elcomopStmt, nil)
	require.Error(t, err)
}

func Test_ValidateStatement(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()
	sf := k256.NewScalarField()
	g := curve.Generator()

	_, comKey, committer, h := mustSetup(t, curve, prng)

	// Honest witness for (L, M, Y).
	lambda, err := sf.Random(prng)
	require.NoError(t, err)
	y, err := sf.Random(prng)
	require.NoError(t, err)
	witness, com := mustElogWitness(t, g, y, lambda, committer)
	bigY := h.ScalarMul(y)
	statement := mustElogStatement(t, com, bigY)

	protocol, err := elog.NewProtocol(curve, comKey, h, prng)
	require.NoError(t, err)

	err = protocol.ValidateStatement(statement, witness)
	require.NoError(t, err)

	// Swap Y for a random point — Schnorr branch should reject.
	wrongY, err := curve.Random(prng)
	require.NoError(t, err)
	wrongStatement := mustElogStatement(t, com, wrongY)
	err = protocol.ValidateStatement(wrongStatement, witness)
	require.Error(t, err)
}

func Test_Name(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()
	_, comKey, _, h := mustSetup(t, curve, prng)

	protocol, err := elog.NewProtocol(curve, comKey, h, prng)
	require.NoError(t, err)

	name := string(protocol.Name())
	require.True(t, strings.Contains(name, string(elcomop.Name)))
	require.True(t, strings.Contains(name, string(schnorrpok.Name)))
	require.True(t, strings.Contains(name, "AND"))
}

func Test_ChallengeLengthAndSoundness(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()
	_, comKey, _, h := mustSetup(t, curve, prng)

	protocol, err := elog.NewProtocol(curve, comKey, h, prng)
	require.NoError(t, err)

	require.Greater(t, protocol.GetChallengeBytesLength(), 0)
	require.GreaterOrEqual(t, protocol.SoundnessError(), uint(1))
	require.GreaterOrEqual(t, protocol.SpecialSoundness(), uint(2))
}

// --- Generic helpers ---

// mustSetup creates an ElGamal keypair, wraps it in an IND-CPA commitment key
// and committer, and samples an independent second generator h.
func mustSetup[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S], prng io.Reader,
) (
	*elgamal.PublicKey[P, S],
	*indcpacom.Key[*elgamal.PublicKey[P, S]],
	*indcpacom.Committer[*elgamal.Nonce[S], *elgamal.Plaintext[P, S], *elgamal.Ciphertext[P, S], *elgamal.PublicKey[P, S]],
	P,
) {
	tb.Helper()

	encScheme, err := elgamal.NewScheme(curve)
	require.NoError(tb, err)
	kg, err := encScheme.Keygen()
	require.NoError(tb, err)
	_, pk, err := kg.Generate(prng)
	require.NoError(tb, err)

	comKey, err := indcpacom.NewKey(pk)
	require.NoError(tb, err)
	comScheme, err := indcpacom.NewScheme(encScheme, comKey)
	require.NoError(tb, err)
	committer, err := comScheme.Committer()
	require.NoError(tb, err)

	h, err := curve.Random(prng)
	require.NoError(tb, err)

	return pk, comKey, committer, h
}

// mustCommit commits to g^y with nonce lambda and returns (elcomopWitness, commitment).
func mustCommit[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB,
	g P,
	y, lambda S,
	committer *indcpacom.Committer[*elgamal.Nonce[S], *elgamal.Plaintext[P, S], *elgamal.Ciphertext[P, S], *elgamal.PublicKey[P, S]],
) (
	*elcomop.Witness[P, S],
	*indcpacom.Commitment[*elgamal.Ciphertext[P, S], *elgamal.Nonce[S], *elgamal.PublicKey[P, S]],
) {
	tb.Helper()

	nonce, err := elgamal.NewNonce(lambda)
	require.NoError(tb, err)
	indcpaWit, err := indcpacom.NewWitness(nonce)
	require.NoError(tb, err)

	plaintext, err := elgamal.NewPlaintext(g.ScalarMul(y))
	require.NoError(tb, err)
	msg, err := indcpacom.NewMessage(plaintext)
	require.NoError(tb, err)

	com, err := committer.CommitWithWitness(msg, indcpaWit)
	require.NoError(tb, err)

	witness, err := elcomop.NewWitness(msg, indcpaWit)
	require.NoError(tb, err)

	return witness, com
}

// mustElogWitness builds a complete elog witness for (y, lambda).
func mustElogWitness[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB,
	g P,
	y, lambda S,
	committer *indcpacom.Committer[*elgamal.Nonce[S], *elgamal.Plaintext[P, S], *elgamal.Ciphertext[P, S], *elgamal.PublicKey[P, S]],
) (
	*elog.Witness[P, S],
	*indcpacom.Commitment[*elgamal.Ciphertext[P, S], *elgamal.Nonce[S], *elgamal.PublicKey[P, S]],
) {
	tb.Helper()

	elcomopWit, com := mustCommit(tb, g, y, lambda, committer)
	schnorrWit := schnorrpok.NewWitness(y)
	witness, err := elog.NewWitness(elcomopWit, schnorrWit)
	require.NoError(tb, err)
	return witness, com
}

// mustElogStatement builds the elog statement (elcomop commitment, Schnorr Y).
func mustElogStatement[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB,
	com *indcpacom.Commitment[*elgamal.Ciphertext[P, S], *elgamal.Nonce[S], *elgamal.PublicKey[P, S]],
	bigY P,
) *elog.Statement[P, S] {
	tb.Helper()

	elcomopStmt, err := elcomop.NewStatement(com)
	require.NoError(tb, err)
	schnorrStmt := schnorrpok.NewStatement[P, S](bigY)
	statement, err := elog.NewStatement(elcomopStmt, schnorrStmt)
	require.NoError(tb, err)
	return statement
}

func testHappyPath[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S],
) {
	tb.Helper()
	prng := pcg.NewRandomised()
	sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](curve.ScalarStructure())

	_, comKey, committer, h := mustSetup(tb, curve, prng)
	g := curve.Generator()

	lambda, err := sf.Random(prng)
	require.NoError(tb, err)
	y, err := sf.Random(prng)
	require.NoError(tb, err)

	witness, com := mustElogWitness(tb, g, y, lambda, committer)
	bigY := h.ScalarMul(y)
	statement := mustElogStatement(tb, com, bigY)

	protocol, err := elog.NewProtocol(curve, comKey, h, prng)
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
	sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](curve.ScalarStructure())

	_, comKey, committer, h := mustSetup(tb, curve, prng)
	g := curve.Generator()

	// Build a statement from a real commitment. The simulator is zero-knowledge
	// for any statement in the image of the homomorphism; using a real
	// commitment keeps us inside that image.
	lambda, err := sf.Random(prng)
	require.NoError(tb, err)
	y, err := sf.Random(prng)
	require.NoError(tb, err)
	_, com := mustCommit(tb, g, y, lambda, committer)
	bigY := h.ScalarMul(y)
	statement := mustElogStatement(tb, com, bigY)

	protocol, err := elog.NewProtocol(curve, comKey, h, prng)
	require.NoError(tb, err)

	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge)
	require.NoError(tb, err)

	commitment, response, err := protocol.RunSimulator(statement, challenge)
	require.NoError(tb, err)

	err = protocol.Verify(statement, commitment, challenge, response)
	require.NoError(tb, err)
}
