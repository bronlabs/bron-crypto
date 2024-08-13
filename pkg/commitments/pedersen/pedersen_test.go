package pedersencommitment_test

import (
	crand "crypto/rand"
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/commitments/pedersen"
	"github.com/stretchr/testify/require"
	"testing"
)

var supportedCurves = []curves.Curve{
	k256.NewCurve(),
	p256.NewCurve(),
	pallas.NewCurve(),
	edwards25519.NewCurve(),
	bls12381.NewG1(),
	bls12381.NewG2(),
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(fmt.Sprintf("curve: %s", curve.Name()), func(t *testing.T) {
			t.Parallel()

			g, err := curve.Random(prng)
			require.NoError(t, err)
			h, err := curve.Random(prng)
			require.NoError(t, err)
			scheme := pedersencommitment.NewScheme(g, h)

			message, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)

			commitment, opening, err := scheme.Commit(message, prng)
			require.NoError(t, err)
			err = scheme.Verify(message, commitment, opening)
			require.NoError(t, err)
		})
	}
}

func Test_ShouldFailOnInvalidCommitmentOrOpening(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			g, err := curve.Random(prng)
			require.NoError(t, err)
			h, err := curve.Random(prng)
			require.NoError(t, err)
			scheme := pedersencommitment.NewScheme(g, h)

			message, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)

			commitmentA, openingA, err := scheme.Commit(message, prng)
			require.NoError(t, err)
			commitmentB, openingB, err := scheme.Commit(message, prng)
			require.NoError(t, err)

			err = scheme.Verify(message, commitmentA, openingB)
			require.Error(t, err)

			err = scheme.Verify(message, commitmentB, openingA)
			require.Error(t, err)
		})
	}
}

func Test_ShouldFailOnNilCommitment(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			g, err := curve.Random(prng)
			require.NoError(t, err)
			h, err := curve.Random(prng)
			require.NoError(t, err)
			scheme := pedersencommitment.NewScheme(g, h)

			message, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)

			_, opening, err := scheme.Commit(message, prng)
			require.NoError(t, err)

			err = scheme.Verify(message, nil, opening)
			require.Error(t, err)
		})
	}
}

func Test_HappyPathAdd(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			g, err := curve.Random(prng)
			require.NoError(t, err)
			h, err := curve.Random(prng)
			require.NoError(t, err)
			scheme := pedersencommitment.NewScheme(g, h)

			messageA, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			messageB, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			messageAPlusB := messageA.Add(messageB)

			commitmentA, openingA, err := scheme.Commit(messageA, prng)
			require.NoError(t, err)
			commitmentB, openingB, err := scheme.Commit(messageB, prng)
			require.NoError(t, err)

			aPlusBCommitment := scheme.CommitmentAdd(commitmentA, commitmentB)
			aPlusBOpening := scheme.OpeningAdd(openingA, openingB)

			err = scheme.Verify(messageAPlusB, aPlusBCommitment, aPlusBOpening)
			require.NoError(t, err)
		})
	}
}

func Test_HappyPathSum(t *testing.T) {
	t.Parallel()
	prng := crand.Reader
	const k = 3

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			g, err := curve.Random(prng)
			require.NoError(t, err)
			h, err := curve.Random(prng)
			require.NoError(t, err)
			scheme := pedersencommitment.NewScheme(g, h)

			var messages [k]pedersencommitment.Message
			for i := range k {
				messages[i], err = curve.ScalarField().Random(prng)
				require.NoError(t, err)
			}

			messagesSum := curve.ScalarField().AdditiveIdentity()
			for _, m := range messages {
				messagesSum = messagesSum.Add(m)
			}

			var commitments [k]pedersencommitment.Commitment
			var openings [k]pedersencommitment.Opening
			for i := range k {
				var err error
				commitments[i], openings[i], err = scheme.Commit(messages[i], prng)
				require.NoError(t, err)
			}

			sumCommitment := scheme.CommitmentSum(commitments[0], commitments[1:]...)
			sumOpening := scheme.OpeningSum(openings[0], openings[1:]...)
			err = scheme.Verify(messagesSum, sumCommitment, sumOpening)
			require.NoError(t, err)
		})
	}
}

func Test_HappyPathSub(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			g, err := curve.Random(prng)
			require.NoError(t, err)
			h, err := curve.Random(prng)
			require.NoError(t, err)
			scheme := pedersencommitment.NewScheme(g, h)

			messageA, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			messageB, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			messageAMinusB := messageA.Sub(messageB)

			commitmentA, openingA, err := scheme.Commit(messageA, prng)
			require.NoError(t, err)
			commitmentB, openingB, err := scheme.Commit(messageB, prng)
			require.NoError(t, err)

			aMinusBCommitment := scheme.CommitmentSub(commitmentA, commitmentB)
			aMinusBOpening := scheme.OpeningSub(openingA, openingB)

			err = scheme.Verify(messageAMinusB, aMinusBCommitment, aMinusBOpening)
			require.NoError(t, err)
		})
	}
}

func Test_HappyPathNeg(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(fmt.Sprintf("curve: %s", curve.Name()), func(t *testing.T) {
			t.Parallel()

			g, err := curve.Random(prng)
			require.NoError(t, err)
			h, err := curve.Random(prng)
			require.NoError(t, err)
			scheme := pedersencommitment.NewScheme(g, h)

			message, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			messageNeg := message.Neg()

			commitment, opening, err := scheme.Commit(message, prng)
			require.NoError(t, err)
			negCommitment := scheme.CommitmentNeg(commitment)
			negOpening := scheme.OpeningNeg(opening)
			err = scheme.Verify(messageNeg, negCommitment, negOpening)
			require.NoError(t, err)
		})
	}
}

func Test_HappyPathScale(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(fmt.Sprintf("curve: %s", curve.Name()), func(t *testing.T) {
			t.Parallel()

			g, err := curve.Random(prng)
			require.NoError(t, err)
			h, err := curve.Random(prng)
			require.NoError(t, err)
			scheme := pedersencommitment.NewScheme(g, h)

			message, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			sc, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			scaledMessage := message.Mul(sc)

			commitment, opening, err := scheme.Commit(message, prng)
			require.NoError(t, err)

			scaledCommitment := scheme.CommitmentScale(commitment, sc)
			scaledOpening := scheme.OpeningScale(opening, sc)
			err = scheme.Verify(scaledMessage, scaledCommitment, scaledOpening)
			require.NoError(t, err)
		})
	}
}

func Test_OpenOnWrongAdd(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			g, err := curve.Random(prng)
			require.NoError(t, err)
			h, err := curve.Random(prng)
			require.NoError(t, err)
			scheme := pedersencommitment.NewScheme(g, h)

			messageA, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			messageB, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			messageAPlusB := messageA.Add(messageB)

			commitmentA, openingA, err := scheme.Commit(messageA, prng)
			require.NoError(t, err)
			commitmentB, openingB, err := scheme.Commit(messageB, prng)
			require.NoError(t, err)
			commitmentBPrime, openingBPrime, err := scheme.Commit(messageB, prng)
			require.NoError(t, err)

			commitmentAPlusB := scheme.CommitmentAdd(commitmentA, commitmentB)
			commitmentAPlusBPrime := scheme.CommitmentAdd(commitmentA, commitmentBPrime)
			openingAPlusB := scheme.OpeningAdd(openingA, openingB)
			openingAPlusBPrime := scheme.OpeningAdd(openingA, openingBPrime)

			err = scheme.Verify(messageAPlusB, commitmentAPlusB, openingAPlusBPrime)
			require.Error(t, err)

			err = scheme.Verify(messageAPlusB, commitmentAPlusBPrime, openingAPlusB)
			require.Error(t, err)
		})
	}
}

func Test_OpenOnWrongScale(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			g, err := curve.Random(prng)
			require.NoError(t, err)
			h, err := curve.Random(prng)
			require.NoError(t, err)
			scheme := pedersencommitment.NewScheme(g, h)

			message, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			scale, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			scaledMessage := message.Mul(scale)

			commitmentA, openingA, err := scheme.Commit(message, prng)
			require.NoError(t, err)
			commitmentB, openingB, err := scheme.Commit(message, prng)
			require.NoError(t, err)

			commitmentAScaled := scheme.CommitmentScale(commitmentA, scale)
			commitmentBScaled := scheme.CommitmentScale(commitmentB, scale)

			openingAScaled := scheme.OpeningScale(openingA, scale)
			openingBScaled := scheme.OpeningScale(openingB, scale)

			err = scheme.Verify(scaledMessage, commitmentAScaled, openingBScaled)
			require.Error(t, err)

			err = scheme.Verify(scaledMessage, commitmentBScaled, openingAScaled)
			require.Error(t, err)
		})
	}
}
