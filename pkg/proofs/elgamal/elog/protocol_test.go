package elog_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/commitments/indcpacom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/elgamal/elog"
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

// Test_TranscriptMatchesFigure23 pins the transcript shape and the three
// verification equations of CGGMP21 Figure 23 on the concrete components.
func Test_TranscriptMatchesFigure23(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()
	sf := k256.NewScalarField()
	g := curve.Generator()

	pk, comKey, h := mustSetup(t, curve, prng)

	lambda, err := sf.Random(prng)
	require.NoError(t, err)
	y, err := sf.Random(prng)
	require.NoError(t, err)

	nonceWit, com := mustCommit(t, g, y, lambda, comKey)
	witness := mustWitness(t, y, nonceWit)
	statement := mustStatement(t, com, h.ScalarMul(y))

	protocol, err := elog.NewProtocol(curve, comKey, h, prng)
	require.NoError(t, err)

	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(t, err)
	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge)
	require.NoError(t, err)
	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(t, err)
	require.NoError(t, protocol.Verify(statement, commitment, challenge, response))

	// Commitment (A, N, B) in G^3, response (u, z) in F_q^2, statement (L, M, Y) in G^3.
	anb := commitment.Value().Components()
	require.Len(t, anb, 3)
	uz := response.Value().Components()
	require.Len(t, uz, 2)
	lmy := statement.Value().Components()
	require.Len(t, lmy, 3)
	bigA, bigN, bigB := anb[0], anb[1], anb[2]
	u, z := uz[0], uz[1]
	bigL, bigM, bigY := lmy[0], lmy[1], lmy[2]
	bigX := pk.Value()
	e, err := num.N().FromBytes(challenge)
	require.NoError(t, err)

	// g^z = A L^e
	require.True(t, g.ScalarMul(z).Equal(bigA.Add(algebrautils.ScalarMul(bigL, e))))
	// g^u X^z = N M^e
	require.True(t, g.ScalarMul(u).Add(bigX.ScalarMul(z)).Equal(bigN.Add(algebrautils.ScalarMul(bigM, e))))
	// h^u = B Y^e
	require.True(t, h.ScalarMul(u).Equal(bigB.Add(algebrautils.ScalarMul(bigY, e))))
}

// Test_CommitmentNotBoundToY_Rejected covers the scenario where a prover knows
// an opening (g^yPrime, lambda) of (L, M) and the discrete logarithm y of Y
// with yPrime != y. The relation has no witness for such a statement, so both
// candidate witnesses must fail validation and verification.
func Test_CommitmentNotBoundToY_Rejected(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()
	sf := k256.NewScalarField()
	g := curve.Generator()

	_, comKey, h := mustSetup(t, curve, prng)

	lambda, err := sf.Random(prng)
	require.NoError(t, err)
	y, err := sf.Random(prng)
	require.NoError(t, err)
	yPrime, err := sf.Random(prng)
	require.NoError(t, err)
	require.False(t, y.Equal(yPrime))

	// (L, M) commits to g^yPrime while Y = h^y.
	nonceWit, com := mustCommit(t, g, yPrime, lambda, comKey)
	statement := mustStatement(t, com, h.ScalarMul(y))

	protocol, err := elog.NewProtocol(curve, comKey, h, prng)
	require.NoError(t, err)

	candidates := []struct {
		name    string
		witness *elog.Witness[*k256.Scalar]
	}{
		{"dlog of Y with commitment nonce", mustWitness(t, y, nonceWit)},
		{"opening of (L, M)", mustWitness(t, yPrime, nonceWit)},
	}
	for _, candidate := range candidates {
		require.Error(t, protocol.ValidateStatement(statement, candidate.witness), candidate.name)

		commitment, state, err := protocol.ComputeProverCommitment(statement, candidate.witness)
		require.NoError(t, err, candidate.name)
		challenge := make([]byte, protocol.GetChallengeBytesLength())
		_, err = io.ReadFull(prng, challenge)
		require.NoError(t, err, candidate.name)
		response, err := protocol.ComputeProverResponse(statement, candidate.witness, commitment, state, challenge)
		require.NoError(t, err, candidate.name)
		require.Error(t, protocol.Verify(statement, commitment, challenge, response), candidate.name)
	}
}

func Test_WrongWitness(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()
	sf := k256.NewScalarField()
	g := curve.Generator()

	_, comKey, h := mustSetup(t, curve, prng)

	lambda, err := sf.Random(prng)
	require.NoError(t, err)
	y, err := sf.Random(prng)
	require.NoError(t, err)
	_, com := mustCommit(t, g, y, lambda, comKey)
	statement := mustStatement(t, com, h.ScalarMul(y))

	wrongLambda, err := sf.Random(prng)
	require.NoError(t, err)
	wrongY, err := sf.Random(prng)
	require.NoError(t, err)
	wrongNonceWit, err := indcpacom.NewWitness(mustNonce(t, wrongLambda))
	require.NoError(t, err)
	wrongWitness := mustWitness(t, wrongY, wrongNonceWit)

	protocol, err := elog.NewProtocol(curve, comKey, h, prng)
	require.NoError(t, err)

	commitment, state, err := protocol.ComputeProverCommitment(statement, wrongWitness)
	require.NoError(t, err)
	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge)
	require.NoError(t, err)
	response, err := protocol.ComputeProverResponse(statement, wrongWitness, commitment, state, challenge)
	require.NoError(t, err)

	require.Error(t, protocol.Verify(statement, commitment, challenge, response))
}

func Test_ValidateStatement(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()
	sf := k256.NewScalarField()
	g := curve.Generator()

	_, comKey, h := mustSetup(t, curve, prng)

	lambda, err := sf.Random(prng)
	require.NoError(t, err)
	y, err := sf.Random(prng)
	require.NoError(t, err)
	nonceWit, com := mustCommit(t, g, y, lambda, comKey)
	witness := mustWitness(t, y, nonceWit)
	statement := mustStatement(t, com, h.ScalarMul(y))

	protocol, err := elog.NewProtocol(curve, comKey, h, prng)
	require.NoError(t, err)
	require.NoError(t, protocol.ValidateStatement(statement, witness))

	// Swap Y for a random point.
	wrongY, err := curve.Random(prng)
	require.NoError(t, err)
	require.Error(t, protocol.ValidateStatement(mustStatement(t, com, wrongY), witness))

	// Swap (L, M) for a commitment under a different nonce.
	otherLambda, err := sf.Random(prng)
	require.NoError(t, err)
	_, otherCom := mustCommit(t, g, y, otherLambda, comKey)
	require.Error(t, protocol.ValidateStatement(mustStatement(t, otherCom, h.ScalarMul(y)), witness))
}

func Test_NewWitness_Nil(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	sf := k256.NewScalarField()

	y, err := sf.Random(prng)
	require.NoError(t, err)
	lambda, err := sf.Random(prng)
	require.NoError(t, err)
	nonceWit, err := indcpacom.NewWitness(mustNonce(t, lambda))
	require.NoError(t, err)

	var nilScalar *k256.Scalar
	_, err = elog.NewWitness(nilScalar, nonceWit)
	require.Error(t, err)

	_, err = elog.NewWitness(y, nil)
	require.Error(t, err)
}

func Test_NewStatement_Nil(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()
	sf := k256.NewScalarField()
	g := curve.Generator()

	_, comKey, h := mustSetup(t, curve, prng)

	y, err := sf.Random(prng)
	require.NoError(t, err)
	lambda, err := sf.Random(prng)
	require.NoError(t, err)
	_, com := mustCommit(t, g, y, lambda, comKey)

	_, err = elog.NewStatement[*k256.Point, *k256.Scalar](nil, h.ScalarMul(y))
	require.Error(t, err)

	var nilPoint *k256.Point
	_, err = elog.NewStatement(com, nilPoint)
	require.Error(t, err)
}

func Test_NewProtocol_InvalidArguments(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()
	_, comKey, h := mustSetup(t, curve, prng)

	_, err := elog.NewProtocol(curve, comKey, h, nil)
	require.Error(t, err)

	_, err = elog.NewProtocol(curve, comKey, curve.OpIdentity(), prng)
	require.Error(t, err)
}

func Test_Name(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()
	_, comKey, h := mustSetup(t, curve, prng)

	protocol, err := elog.NewProtocol(curve, comKey, h, prng)
	require.NoError(t, err)

	require.Equal(t, elog.Name, protocol.Name())
}

func Test_ChallengeLengthAndSoundness(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()
	_, comKey, h := mustSetup(t, curve, prng)

	protocol, err := elog.NewProtocol(curve, comKey, h, prng)
	require.NoError(t, err)

	require.Positive(t, protocol.GetChallengeBytesLength())
	require.GreaterOrEqual(t, protocol.SoundnessError(), uint(1))
	require.GreaterOrEqual(t, protocol.SpecialSoundness(), uint(2))
}

// --- Generic helpers ---

// mustSetup creates an ElGamal keypair, wraps it in an IND-CPA commitment key,
// and samples an independent second base h.
func mustSetup[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S], prng io.Reader,
) (
	*elgamal.PublicKey[P, S],
	*indcpacom.CommitmentKey[*elgamal.PublicKey[P, S], *elgamal.Plaintext[P, S], *elgamal.Nonce[S], *elgamal.Ciphertext[P, S]],
	P,
) {
	tb.Helper()

	sk, err := elgamal.SampleSecretKey(curve, prng)
	require.NoError(tb, err)

	comKey, err := indcpacom.NewCommitmentKey(sk.Public())
	require.NoError(tb, err)

	h, err := curve.Random(prng)
	require.NoError(tb, err)

	return sk.Public(), comKey, h
}

func mustNonce[S algebra.PrimeFieldElement[S]](tb testing.TB, lambda S) *elgamal.Nonce[S] {
	tb.Helper()

	nonce, err := elgamal.NewNonce(lambda)
	require.NoError(tb, err)
	return nonce
}

// mustCommit commits to g^y with nonce lambda and returns the nonce witness
// and the commitment (L, M).
func mustCommit[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB,
	g P,
	y, lambda S,
	committer *indcpacom.CommitmentKey[*elgamal.PublicKey[P, S], *elgamal.Plaintext[P, S], *elgamal.Nonce[S], *elgamal.Ciphertext[P, S]],
) (
	*indcpacom.Witness[*elgamal.Nonce[S]],
	*indcpacom.Commitment[*elgamal.Ciphertext[P, S]],
) {
	tb.Helper()

	nonceWit, err := indcpacom.NewWitness(mustNonce(tb, lambda))
	require.NoError(tb, err)

	plaintext, err := elgamal.NewPlaintext(g.ScalarMul(y))
	require.NoError(tb, err)
	msg, err := indcpacom.NewMessage(plaintext)
	require.NoError(tb, err)

	com, err := committer.CommitWithWitness(msg, nonceWit)
	require.NoError(tb, err)

	return nonceWit, com
}

// mustWitness builds the elog witness (y, lambda).
func mustWitness[S algebra.PrimeFieldElement[S]](tb testing.TB, y S, nonceWit *indcpacom.Witness[*elgamal.Nonce[S]]) *elog.Witness[S] {
	tb.Helper()

	witness, err := elog.NewWitness(y, nonceWit)
	require.NoError(tb, err)
	return witness
}

// mustStatement builds the elog statement (L, M, Y).
func mustStatement[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB,
	com *indcpacom.Commitment[*elgamal.Ciphertext[P, S]],
	bigY P,
) *elog.Statement[P, S] {
	tb.Helper()

	statement, err := elog.NewStatement(com, bigY)
	require.NoError(tb, err)
	return statement
}

func testHappyPath[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S],
) {
	tb.Helper()
	prng := pcg.NewRandomised()
	sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](curve.ScalarStructure())

	_, comKey, h := mustSetup(tb, curve, prng)
	g := curve.Generator()

	lambda, err := sf.Random(prng)
	require.NoError(tb, err)
	y, err := sf.Random(prng)
	require.NoError(tb, err)

	nonceWit, com := mustCommit(tb, g, y, lambda, comKey)
	witness := mustWitness(tb, y, nonceWit)
	statement := mustStatement(tb, com, h.ScalarMul(y))

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

	_, comKey, h := mustSetup(tb, curve, prng)
	g := curve.Generator()

	// Build a statement from a real commitment so that it lies in the image of
	// the homomorphism.
	lambda, err := sf.Random(prng)
	require.NoError(tb, err)
	y, err := sf.Random(prng)
	require.NoError(tb, err)
	_, com := mustCommit(tb, g, y, lambda, comKey)
	statement := mustStatement(tb, com, h.ScalarMul(y))

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

func testExtractor[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S],
) {
	tb.Helper()
	prng := pcg.NewRandomised()
	sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](curve.ScalarStructure())

	_, comKey, h := mustSetup(tb, curve, prng)
	g := curve.Generator()

	lambda, err := sf.Random(prng)
	require.NoError(tb, err)
	y, err := sf.Random(prng)
	require.NoError(tb, err)

	nonceWit, com := mustCommit(tb, g, y, lambda, comKey)
	witness := mustWitness(tb, y, nonceWit)
	statement := mustStatement(tb, com, h.ScalarMul(y))

	protocol, err := elog.NewProtocol(curve, comKey, h, prng)
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

func testAnchor[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S],
) {
	tb.Helper()
	prng := pcg.NewRandomised()

	_, comKey, h := mustSetup(tb, curve, prng)

	protocol, err := elog.NewProtocol(curve, comKey, h, prng)
	require.NoError(tb, err)

	anchor := protocol.Anchor()

	// L() is the group order.
	expectedL, err := num.N().FromBytes(curve.Order().Bytes())
	require.NoError(tb, err)
	require.True(tb, anchor.L().Equal(expectedL))

	preImageGroup := protocol.PreImageGroup()
	imageGroup := protocol.ImageGroup()
	expectedPreImage := preImageGroup.OpIdentity()

	// PreImage(x) is the identity of the pre-image group for every x, and
	// x^L is the image-group identity, which is phi of that pre-image.
	for range 8 {
		x, err := imageGroup.Random(prng)
		require.NoError(tb, err)
		require.True(tb, anchor.PreImage(x).Equal(expectedPreImage))
		require.True(tb, algebrautils.ScalarMul(x, anchor.L()).IsOpIdentity())
	}
}

// Test_Verify_MalformedProofRejected checks that a commitment or response of the
// wrong shape fails verification instead of crashing the verifier. Both values
// are chosen by the prover and arrive over the wire, whichever compiler or
// interactive verifier is in use, and the direct-power decoder accepts any
// component count.
func Test_Verify_MalformedProofRejected(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		testMalformedProofRejected(t, k256.NewCurve())
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		testMalformedProofRejected(t, p256.NewCurve())
	})
}

func testMalformedProofRejected[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S],
) {
	tb.Helper()
	prng := pcg.NewRandomised()
	sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](curve.ScalarStructure())

	_, comKey, h := mustSetup(tb, curve, prng)
	g := curve.Generator()

	lambda, err := sf.Random(prng)
	require.NoError(tb, err)
	y, err := sf.Random(prng)
	require.NoError(tb, err)

	nonceWit, com := mustCommit(tb, g, y, lambda, comKey)
	witness := mustWitness(tb, y, nonceWit)
	statement := mustStatement(tb, com, h.ScalarMul(y))

	protocol, err := elog.NewProtocol(curve, comKey, h, prng)
	require.NoError(tb, err)

	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(tb, err)
	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge)
	require.NoError(tb, err)
	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(tb, err)
	require.NoError(tb, protocol.Verify(statement, commitment, challenge, response))

	// A commitment with any component count other than three (A, N, B). The
	// zero value has no components, which is what the decoder yields for an
	// empty component list.
	badCommitments := []*constructions.FiniteDirectPowerModuleElement[P, S]{
		{},
		mustPowerModuleElement(tb, curve, g, 1),
		mustPowerModuleElement(tb, curve, g, 2),
		mustPowerModuleElement(tb, curve, g, 4),
	}
	for _, bad := range badCommitments {
		var verifyErr error
		require.NotPanics(tb, func() {
			verifyErr = protocol.Verify(statement, &elog.Commitment[P, S]{A: bad}, challenge, response)
		})
		require.ErrorIs(tb, verifyErr, proofs.ErrVerificationFailed)
	}

	// A response with any component count other than two (u, z).
	badResponses := []*constructions.FiniteDirectPowerRingElement[S]{
		{},
		mustPowerRingElement(tb, sf, y, 1),
		mustPowerRingElement(tb, sf, y, 3),
	}
	for _, bad := range badResponses {
		var verifyErr error
		require.NotPanics(tb, func() {
			verifyErr = protocol.Verify(statement, commitment, challenge, &elog.Response[S]{Z: bad})
		})
		require.ErrorIs(tb, verifyErr, proofs.ErrVerificationFailed)
	}
}

// mustPowerModuleElement builds an element of G^arity whose components are all g.
func mustPowerModuleElement[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S], g P, arity uint,
) *constructions.FiniteDirectPowerModuleElement[P, S] {
	tb.Helper()

	module, err := constructions.NewFiniteDirectPowerModule(curve, arity)
	require.NoError(tb, err)
	components := make([]P, arity)
	for i := range components {
		components[i] = g
	}
	element, err := module.New(components...)
	require.NoError(tb, err)
	return element
}

// mustPowerRingElement builds an element of F_q^arity whose components are all s.
func mustPowerRingElement[S algebra.PrimeFieldElement[S]](
	tb testing.TB, sf algebra.PrimeField[S], s S, arity uint,
) *constructions.FiniteDirectPowerRingElement[S] {
	tb.Helper()

	ring, err := constructions.NewFiniteDirectPowerRing(sf, arity)
	require.NoError(tb, err)
	components := make([]S, arity)
	for i := range components {
		components[i] = s
	}
	element, err := ring.New(components...)
	require.NoError(tb, err)
	return element
}
