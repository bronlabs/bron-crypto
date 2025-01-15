package elgamalcommitments_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/p256"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/pallas"
	elgamalcommitments "github.com/bronlabs/krypton-primitives/pkg/commitments/elgamal"
)

var supportedCurves = []curves.Curve{
	k256.NewCurve(),
	p256.NewCurve(),
	pallas.NewCurve(),
	edwards25519.NewCurve(),
	bls12381.NewG1(),
	bls12381.NewG2(),
}

func TestSimpleHappyPath(t *testing.T) {
	t.Parallel()

	sessionId := []byte("elgamalHappyPathSessionId")
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			publicKey, err := curve.Random(crand.Reader)
			require.NoError(t, err)

			message, err := curve.Random(crand.Reader)
			require.NoError(t, err)

			committer, err := elgamalcommitments.NewCommitter(sessionId, publicKey, prng)
			require.NoError(t, err)

			commitment, opening, err := committer.Commit(message)
			require.NoError(t, err)
			require.True(t, message.Equal(opening.GetMessage()))

			verifier, err := elgamalcommitments.NewVerifier(sessionId, publicKey)
			require.NoError(t, err)

			err = verifier.Verify(commitment, opening)
			require.NoError(t, err)
		})
	}
}
func TestShouldFailOnNilCommitment(t *testing.T) {
	t.Parallel()

	sessionId := []byte("shouldFailOnNilCommitmentSessionId")
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			publicKey, err := curve.Random(prng)
			require.NoError(t, err)
			message, err := curve.Random(prng)
			require.NoError(t, err)

			committer, err := elgamalcommitments.NewCommitter(sessionId, publicKey, prng)
			require.NoError(t, err)

			_, opening, err := committer.Commit(message)
			require.NoError(t, err)

			verifier, err := elgamalcommitments.NewVerifier(sessionId, publicKey)
			require.NoError(t, err)

			err = verifier.Verify(nil, opening)
			require.Error(t, err)
		})
	}
}

func TestHappyPathCombine(t *testing.T) {
	t.Parallel()

	sessionId := []byte("happyPathCombineSessionId")
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			publicKey, err := curve.Random(prng)
			require.NoError(t, err)
			messageA, err := curve.Random(prng)
			require.NoError(t, err)
			messageB, err := curve.Random(prng)
			require.NoError(t, err)
			messageAPlusB := messageA.Add(messageB)

			committer, err := elgamalcommitments.NewCommitter(sessionId, publicKey, prng)
			require.NoError(t, err)

			commitmentA, openingA, err := committer.Commit(messageA)
			require.NoError(t, err)
			commitmentB, openingB, err := committer.Commit(messageB)
			require.NoError(t, err)

			verifier, err := elgamalcommitments.NewVerifier(sessionId, publicKey)
			require.NoError(t, err)

			commitmentAPlusB, err := verifier.CombineCommitments(commitmentA, commitmentB)
			require.NoError(t, err)
			openingAPlusB, err := verifier.CombineOpenings(openingA, openingB)
			require.NoError(t, err)

			err = verifier.Verify(commitmentAPlusB, openingAPlusB)
			require.NoError(t, err)
			require.True(t, openingAPlusB.GetMessage().Equal(messageAPlusB))
		})
	}
}

func TestOpenOnWrongCombine(t *testing.T) {
	t.Parallel()

	sessionId := []byte("happyPathCombineSessionId")
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			publicKey, err := curve.Random(prng)
			require.NoError(t, err)
			messageA, err := curve.Random(prng)
			require.NoError(t, err)
			messageB, err := curve.Random(prng)
			require.NoError(t, err)
			messageAPlusB := messageA.Add(messageB)

			committer, err := elgamalcommitments.NewCommitter(sessionId, publicKey, prng)
			require.NoError(t, err)

			commitmentA, openingA, err := committer.Commit(messageA)
			require.NoError(t, err)
			commitmentB, openingB, err := committer.Commit(messageB)
			require.NoError(t, err)
			commitmentBPrime, openingBPrime, err := committer.Commit(messageB)
			require.NoError(t, err)

			verifier, err := elgamalcommitments.NewVerifier(sessionId, publicKey)
			require.NoError(t, err)

			commitmentAPlusB, err := verifier.CombineCommitments(commitmentA, commitmentB)
			require.NoError(t, err)
			commitmentAPlusBPrime, err := verifier.CombineCommitments(commitmentA, commitmentBPrime)
			require.NoError(t, err)
			openingAPlusB, err := verifier.CombineOpenings(openingA, openingB)
			require.NoError(t, err)
			openingAPlusBPrime, err := verifier.CombineOpenings(openingA, openingBPrime)
			require.NoError(t, err)

			require.True(t, messageAPlusB.Equal(openingAPlusB.GetMessage()))
			require.True(t, messageAPlusB.Equal(openingAPlusBPrime.GetMessage()))

			err = verifier.Verify(commitmentAPlusB, openingAPlusBPrime)
			require.Error(t, err)

			err = verifier.Verify(commitmentAPlusBPrime, openingAPlusB)
			require.Error(t, err)
		})
	}
}

func TestHappyScale(t *testing.T) {
	t.Parallel()

	sessionId := []byte("happyPathScaleSessionId")
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			publicKey, err := curve.Random(prng)
			require.NoError(t, err)
			message, err := curve.Random(prng)
			require.NoError(t, err)
			scale, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			scaledMessage := message.ScalarMul(scale)

			committer, err := elgamalcommitments.NewCommitter(sessionId, publicKey, prng)
			require.NoError(t, err)

			commitment, opening, err := committer.Commit(message)
			require.NoError(t, err)

			verifier, err := elgamalcommitments.NewVerifier(sessionId, publicKey)
			require.NoError(t, err)

			scaledCommitment, err := verifier.ScaleCommitment(commitment, scale.Nat())
			require.NoError(t, err)

			scaledOpening, err := verifier.ScaleOpening(opening, scale.Nat())
			require.NoError(t, err)

			err = verifier.Verify(scaledCommitment, scaledOpening)
			require.NoError(t, err)
			require.True(t, scaledOpening.GetMessage().Equal(scaledMessage))
		})
	}
}

func TestOpenOnWrongScale(t *testing.T) {
	t.Parallel()

	sessionId := []byte("openOnWrongScaleSessionId")
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			publicKey, err := curve.Random(prng)
			require.NoError(t, err)
			message, err := curve.Random(prng)
			require.NoError(t, err)
			scale, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			scaledMessage := message.ScalarMul(scale)

			committer, err := elgamalcommitments.NewCommitter(sessionId, publicKey, prng)
			require.NoError(t, err)

			commitmentA, openingA, err := committer.Commit(message)
			require.NoError(t, err)
			commitmentB, openingB, err := committer.Commit(message)
			require.NoError(t, err)

			verifier, err := elgamalcommitments.NewVerifier(sessionId, publicKey)
			require.NoError(t, err)

			commitmentAScaled, err := verifier.ScaleCommitment(commitmentA, scale.Nat())
			require.NoError(t, err)
			commitmentBScaled, err := verifier.ScaleCommitment(commitmentB, scale.Nat())
			require.NoError(t, err)
			openingAScaled, err := verifier.ScaleOpening(openingA, scale.Nat())
			require.NoError(t, err)
			openingBScaled, err := verifier.ScaleOpening(openingB, scale.Nat())
			require.NoError(t, err)

			require.True(t, openingAScaled.GetMessage().Equal(scaledMessage))
			require.True(t, openingBScaled.GetMessage().Equal(scaledMessage))

			err = verifier.Verify(commitmentAScaled, openingBScaled)
			require.Error(t, err)

			err = verifier.Verify(commitmentBScaled, openingAScaled)
			require.Error(t, err)
		})
	}
}
