package pedersencomm_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/comm/pedersencomm"
)

var supportedCurves = []curves.Curve{
	k256.NewCurve(),
	p256.NewCurve(),
	pallas.NewCurve(),
	edwards25519.NewCurve(),
	bls12381.NewG1(),
	bls12381.NewG2(),
}

func TestHappyPathCommitment(t *testing.T) {
	t.Parallel()

	sessionId := []byte("happyPathCommitmentSessionId")
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			committer, err := pedersencomm.NewCommitter(sessionId, curve, prng)
			require.NoError(t, err)
			require.NotNil(t, committer)

			verifier, err := pedersencomm.NewVerifier(sessionId, curve)
			require.NoError(t, err)
			require.NotNil(t, verifier)

			message, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)

			commit, opening, err := committer.Commit(message)
			require.NoError(t, err)
			require.NotNil(t, commit)
			require.NotNil(t, opening)

			err = verifier.Verify(commit, opening)
			require.NoError(t, err)
		})
	}
}

func TestShouldFailOnInvalidCommitmentOrOpening(t *testing.T) {
	t.Parallel()

	sessionId := []byte("shouldFailOnInvalidCommitmentOrOpeningSessionId")
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			message, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)

			committer, err := pedersencomm.NewCommitter(sessionId, curve, prng)
			require.NoError(t, err)

			commitmentA, openingA, err := committer.Commit(message)
			require.NoError(t, err)
			commitmentB, openingB, err := committer.Commit(message)
			require.NoError(t, err)
			require.True(t, openingA.Message().Equal(openingB.Message()))

			verifier, err := pedersencomm.NewVerifier(sessionId, curve)
			require.NoError(t, err)

			err = verifier.Verify(commitmentA, openingB)
			require.Error(t, err)

			err = verifier.Verify(commitmentB, openingA)
			require.Error(t, err)
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

			message, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)

			committer, err := pedersencomm.NewCommitter(sessionId, curve, prng)
			require.NoError(t, err)

			_, opening, err := committer.Commit(message)
			require.NoError(t, err)

			verifier, err := pedersencomm.NewVerifier(sessionId, curve)
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

			messageA, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			messageB, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			messageAPlusB := messageA.Add(messageB)

			committer, err := pedersencomm.NewCommitter(sessionId, curve, prng)
			require.NoError(t, err)

			commitmentA, openingA, err := committer.Commit(messageA)
			require.NoError(t, err)
			commitmentB, openingB, err := committer.Commit(messageB)
			require.NoError(t, err)

			verifier, err := pedersencomm.NewVerifier(sessionId, curve)
			require.NoError(t, err)

			commitmentAPlusB, err := verifier.CombineCommitments(commitmentA, commitmentB)
			require.NoError(t, err)
			openingAPlusB, err := verifier.CombineOpenings(openingA, openingB)
			require.NoError(t, err)

			err = verifier.Verify(commitmentAPlusB, openingAPlusB)
			require.NoError(t, err)
			require.True(t, openingAPlusB.Message().Equal(messageAPlusB))
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

			messageA, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			messageB, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			messageAPlusB := messageA.Add(messageB)

			committer, err := pedersencomm.NewCommitter(sessionId, curve, prng)
			require.NoError(t, err)

			commitmentA, openingA, err := committer.Commit(messageA)
			require.NoError(t, err)
			commitmentB, openingB, err := committer.Commit(messageB)
			require.NoError(t, err)
			commitmentBPrime, openingBPrime, err := committer.Commit(messageB)
			require.NoError(t, err)

			verifier, err := pedersencomm.NewVerifier(sessionId, curve)
			require.NoError(t, err)

			commitmentAPlusB, err := verifier.CombineCommitments(commitmentA, commitmentB)
			require.NoError(t, err)
			commitmentAPlusBPrime, err := verifier.CombineCommitments(commitmentA, commitmentBPrime)
			require.NoError(t, err)
			openingAPlusB, err := verifier.CombineOpenings(openingA, openingB)
			require.NoError(t, err)
			openingAPlusBPrime, err := verifier.CombineOpenings(openingA, openingBPrime)
			require.NoError(t, err)

			require.True(t, messageAPlusB.Equal(openingAPlusB.Message()))
			require.True(t, messageAPlusB.Equal(openingAPlusBPrime.Message()))

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

			message, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			scale, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			scaledMessage := message.Mul(scale)

			committer, err := pedersencomm.NewCommitter(sessionId, curve, prng)
			require.NoError(t, err)

			commitment, opening, err := committer.Commit(message)
			require.NoError(t, err)

			verifier, err := pedersencomm.NewVerifier(sessionId, curve)
			require.NoError(t, err)

			scaledCommitment, err := verifier.ScaleCommitment(commitment, scale.Nat())
			require.NoError(t, err)

			scaledOpening, err := verifier.ScaleOpening(opening, scale.Nat())
			require.NoError(t, err)

			err = verifier.Verify(scaledCommitment, scaledOpening)
			require.NoError(t, err)
			require.True(t, scaledOpening.Message().Equal(scaledMessage))
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

			message, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			scale, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			scaledMessage := message.Mul(scale)

			committer, err := pedersencomm.NewCommitter(sessionId, curve, prng)
			require.NoError(t, err)

			commitmentA, openingA, err := committer.Commit(message)
			require.NoError(t, err)
			commitmentB, openingB, err := committer.Commit(message)
			require.NoError(t, err)

			verifier, err := pedersencomm.NewVerifier(sessionId, curve)
			require.NoError(t, err)

			commitmentAScaled, err := verifier.ScaleCommitment(commitmentA, scale.Nat())
			require.NoError(t, err)
			commitmentBScaled, err := verifier.ScaleCommitment(commitmentB, scale.Nat())
			require.NoError(t, err)
			openingAScaled, err := verifier.ScaleOpening(openingA, scale.Nat())
			require.NoError(t, err)
			openingBScaled, err := verifier.ScaleOpening(openingB, scale.Nat())
			require.NoError(t, err)

			require.True(t, openingAScaled.Message().Equal(scaledMessage))
			require.True(t, openingBScaled.Message().Equal(scaledMessage))

			err = verifier.Verify(commitmentAScaled, openingBScaled)
			require.Error(t, err)

			err = verifier.Verify(commitmentBScaled, openingAScaled)
			require.Error(t, err)
		})
	}
}
