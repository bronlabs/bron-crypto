package elcomop_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/commitments/indcpacom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
	"github.com/bronlabs/bron-crypto/pkg/proofs/elgamal/elcomop"
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

func Test_Anchor(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		testAnchor(t, k256.NewCurve())
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		testAnchor(t, p256.NewCurve())
	})
}

func Test_WrongWitness(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()
	sf := k256.NewScalarField()

	pk, comKey, committer := mustSetup(t, curve, prng)

	lambda, err := sf.Random(prng)
	require.NoError(t, err)
	y, err := sf.Random(prng)
	require.NoError(t, err)

	_, comStatement := mustCommit(t, curve.Generator(), y, lambda, committer)

	protocol, err := elcomop.NewProtocol(curve, comKey, prng)
	require.NoError(t, err)

	statement, err := elcomop.NewStatement(comStatement)
	require.NoError(t, err)

	// Build a wrong witness (unrelated lambda and y).
	wrongLambda, err := sf.Random(prng)
	require.NoError(t, err)
	wrongY, err := sf.Random(prng)
	require.NoError(t, err)
	wrongWitness := mustBuildWitness(t, curve.Generator(), wrongLambda, wrongY)

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

// --- Generic helpers ---

// mustSetup creates an ElGamal keypair, wraps the public key in an IND-CPA
// commitment key, and returns a ready-to-use committer.
func mustSetup[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S], prng io.Reader,
) (
	*elgamal.PublicKey[P, S],
	*indcpacom.Key[*elgamal.PublicKey[P, S]],
	*indcpacom.Committer[*elgamal.Nonce[S], *elgamal.Plaintext[P, S], *elgamal.Ciphertext[P, S], *elgamal.PublicKey[P, S]],
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

	return pk, comKey, committer
}

// mustCommit builds an ElGamal/IND-CPA commitment of g^y with nonce lambda, and
// returns both the indcpacom commitment and the elcomop witness components.
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

// mustBuildWitness constructs an elcomop witness from raw scalars, bypassing
// any relation to a real commitment (useful for negative tests).
func mustBuildWitness[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, g P, lambda, y S,
) *elcomop.Witness[P, S] {
	tb.Helper()

	nonce, err := elgamal.NewNonce(lambda)
	require.NoError(tb, err)
	indcpaWit, err := indcpacom.NewWitness(nonce)
	require.NoError(tb, err)
	plaintext, err := elgamal.NewPlaintext(g.ScalarMul(y))
	require.NoError(tb, err)
	msg, err := indcpacom.NewMessage(plaintext)
	require.NoError(tb, err)
	witness, err := elcomop.NewWitness(msg, indcpaWit)
	require.NoError(tb, err)
	return witness
}

func testHappyPath[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S],
) {
	tb.Helper()
	prng := pcg.NewRandomised()
	sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](curve.ScalarStructure())

	_, comKey, committer := mustSetup(tb, curve, prng)

	lambda, err := sf.Random(prng)
	require.NoError(tb, err)
	y, err := sf.Random(prng)
	require.NoError(tb, err)

	witness, com := mustCommit(tb, curve.Generator(), y, lambda, committer)

	protocol, err := elcomop.NewProtocol(curve, comKey, prng)
	require.NoError(tb, err)

	statement, err := elcomop.NewStatement(com)
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

	_, comKey, committer := mustSetup(tb, curve, prng)
	protocol, err := elcomop.NewProtocol(curve, comKey, prng)
	require.NoError(tb, err)

	// Random statement produced by a well-formed commitment (simulator is
	// zero-knowledge for any valid statement in the image of phi, and using a
	// real commitment avoids relying on points outside the image).
	lambda, err := sf.Random(prng)
	require.NoError(tb, err)
	y, err := sf.Random(prng)
	require.NoError(tb, err)
	_, com := mustCommit(tb, curve.Generator(), y, lambda, committer)

	statement, err := elcomop.NewStatement(com)
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

	_, comKey, committer := mustSetup(tb, curve, prng)

	lambda, err := sf.Random(prng)
	require.NoError(tb, err)
	y, err := sf.Random(prng)
	require.NoError(tb, err)

	witness, com := mustCommit(tb, curve.Generator(), y, lambda, committer)

	protocol, err := elcomop.NewProtocol(curve, comKey, prng)
	require.NoError(tb, err)

	statement, err := elcomop.NewStatement(com)
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
	zi := []*elcomop.Response[P, S]{response1, response2}

	wExtracted, err := protocol.Extract(statement, commitment, ei, zi)
	require.NoError(tb, err)
	require.True(tb, wExtracted.Value().Equal(witness.Value()))
}

func testAnchor[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S],
) {
	tb.Helper()
	prng := pcg.NewRandomised()

	_, comKey, _ := mustSetup(tb, curve, prng)

	protocol, err := elcomop.NewProtocol(curve, comKey, prng)
	require.NoError(tb, err)

	anchor := protocol.Anchor()

	// L() is the group order.
	expectedL, err := num.N().FromBytes(curve.Order().Bytes())
	require.NoError(tb, err)
	require.True(tb, anchor.L().Equal(expectedL))

	preImageGroup := protocol.PreImageGroup()
	imageGroup := protocol.ImageGroup()
	expectedPreImage := preImageGroup.OpIdentity()

	// PreImage(x) is the identity of the pre-image group for every x.
	for range 8 {
		x, err := imageGroup.Random(prng)
		require.NoError(tb, err)
		require.True(tb, anchor.PreImage(x).Equal(expectedPreImage))
	}

	// Anchor invariant: phi(PreImage(x)) == x * L(). The pre-image is the
	// pre-image-group identity, so both sides collapse to the image-group
	// identity — verified here by checking x^L directly, since phi itself
	// is implemented via elgamal encryption which rejects identity inputs.
	for range 8 {
		x, err := imageGroup.Random(prng)
		require.NoError(tb, err)
		require.True(tb, algebrautils.ScalarMul(x, anchor.L()).IsOpIdentity())
	}
}
