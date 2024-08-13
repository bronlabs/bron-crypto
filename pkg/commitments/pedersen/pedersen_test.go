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

			commitment, witness := scheme.Commit(message, prng)
			err = scheme.Verify(message, commitment, witness)
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

			commitmentA, witnessA := scheme.Commit(message, prng)
			commitmentB, witnessB := scheme.Commit(message, prng)

			err = scheme.Verify(message, commitmentA, witnessB)
			require.Error(t, err)

			err = scheme.Verify(message, commitmentB, witnessA)
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

			_, witness := scheme.Commit(message, prng)
			//require.NoError(t, err)

			err = scheme.Verify(message, nil, witness)
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

			commitmentA, witnessA := scheme.Commit(messageA, prng)
			commitmentB, witnessB := scheme.Commit(messageB, prng)

			aPlusBCommitment := scheme.CommitmentAdd(commitmentA, commitmentB)
			aPlusBWitness := scheme.WitnessAdd(witnessA, witnessB)

			err = scheme.Verify(messageAPlusB, aPlusBCommitment, aPlusBWitness)
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
			var witnesses [k]pedersencommitment.Witness
			for i := range k {
				commitments[i], witnesses[i] = scheme.Commit(messages[i], prng)
				//require.NoError(t, err)
			}

			sumCommitment := scheme.CommitmentSum(commitments[0], commitments[1:]...)
			sumWitness := scheme.WitnessSum(witnesses[0], witnesses[1:]...)
			err = scheme.Verify(messagesSum, sumCommitment, sumWitness)
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

			commitmentA, witnessA := scheme.Commit(messageA, prng)
			commitmentB, witnessB := scheme.Commit(messageB, prng)

			aMinusBCommitment := scheme.CommitmentSub(commitmentA, commitmentB)
			aMinusBWitness := scheme.WitnessSub(witnessA, witnessB)

			err = scheme.Verify(messageAMinusB, aMinusBCommitment, aMinusBWitness)
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

			commitment, witness := scheme.Commit(message, prng)
			negCommitment := scheme.CommitmentNeg(commitment)
			negWitness := scheme.WitnessNeg(witness)
			err = scheme.Verify(messageNeg, negCommitment, negWitness)
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

			commitment, witness := scheme.Commit(message, prng)
			scaledCommitment := scheme.CommitmentScale(commitment, sc)
			scaledWitness := scheme.WitnessScale(witness, sc)
			err = scheme.Verify(scaledMessage, scaledCommitment, scaledWitness)
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

			commitmentA, witnessA := scheme.Commit(messageA, prng)
			commitmentB, witnessB := scheme.Commit(messageB, prng)
			commitmentBPrime, witnessBPrime := scheme.Commit(messageB, prng)

			commitmentAPlusB := scheme.CommitmentAdd(commitmentA, commitmentB)
			commitmentAPlusBPrime := scheme.CommitmentAdd(commitmentA, commitmentBPrime)
			witnessAPlusB := scheme.WitnessAdd(witnessA, witnessB)
			witnessAPlusBPrime := scheme.WitnessAdd(witnessA, witnessBPrime)

			err = scheme.Verify(messageAPlusB, commitmentAPlusB, witnessAPlusBPrime)
			require.Error(t, err)

			err = scheme.Verify(messageAPlusB, commitmentAPlusBPrime, witnessAPlusB)
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

			commitmentA, witnessA := scheme.Commit(message, prng)
			commitmentB, witnessB := scheme.Commit(message, prng)

			commitmentAScaled := scheme.CommitmentScale(commitmentA, scale)
			commitmentBScaled := scheme.CommitmentScale(commitmentB, scale)

			openingAScaled := scheme.WitnessScale(witnessA, scale)
			openingBScaled := scheme.WitnessScale(witnessB, scale)

			err = scheme.Verify(scaledMessage, commitmentAScaled, openingBScaled)
			require.Error(t, err)

			err = scheme.Verify(scaledMessage, commitmentBScaled, openingAScaled)
			require.Error(t, err)
		})
	}
}
