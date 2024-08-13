package ecelgamalcommitment_test

import (
	crand "crypto/rand"
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/commitments/ecelgamal"
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
			pk := &ecelgamalcommitment.PublicKey{
				G: g,
				H: h,
			}
			scheme := ecelgamalcommitment.NewScheme(pk)

			message, err := curve.Random(prng)
			require.NoError(t, err)

			commitment, witness, err := scheme.Commit(message, prng)
			require.NoError(t, err)

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
			pk := &ecelgamalcommitment.PublicKey{
				G: g,
				H: h,
			}
			scheme := ecelgamalcommitment.NewScheme(pk)

			message, err := curve.Random(prng)
			require.NoError(t, err)

			commitmentA, witnessA, err := scheme.Commit(message, prng)
			require.NoError(t, err)
			commitmentB, witnessB, err := scheme.Commit(message, prng)
			require.NoError(t, err)

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
			pk := &ecelgamalcommitment.PublicKey{
				G: g,
				H: h,
			}
			scheme := ecelgamalcommitment.NewScheme(pk)

			message, err := curve.Random(prng)
			require.NoError(t, err)

			_, witness, err := scheme.Commit(message, prng)
			require.NoError(t, err)

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
			pk := &ecelgamalcommitment.PublicKey{
				G: g,
				H: h,
			}
			scheme := ecelgamalcommitment.NewScheme(pk)

			messageA, err := curve.Random(prng)
			require.NoError(t, err)
			messageB, err := curve.Random(prng)
			require.NoError(t, err)
			messageAPlusB := messageA.Add(messageB)

			commitmentA, witnessA, err := scheme.Commit(messageA, prng)
			require.NoError(t, err)
			commitmentB, witnessB, err := scheme.Commit(messageB, prng)
			require.NoError(t, err)

			aPlusBCommitment := scheme.CommitmentAdd(commitmentA, commitmentB)
			aPlusBWitness := scheme.OpeningAdd(witnessA, witnessB)

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
			pk := &ecelgamalcommitment.PublicKey{
				G: g,
				H: h,
			}
			scheme := ecelgamalcommitment.NewScheme(pk)

			var messages [k]ecelgamalcommitment.Message
			for i := range k {
				messages[i], err = curve.Random(prng)
				require.NoError(t, err)
			}

			messagesSum := curve.AdditiveIdentity()
			for _, m := range messages {
				messagesSum = messagesSum.Add(m)
			}

			var commitments [k]*ecelgamalcommitment.Commitment
			var witnesses [k]ecelgamalcommitment.Opening
			for i := range k {
				var err error
				commitments[i], witnesses[i], err = scheme.Commit(messages[i], prng)
				require.NoError(t, err)
			}

			sumCommitment := scheme.CommitmentSum(commitments[0], commitments[1:]...)
			sumWitness := scheme.OpeningSum(witnesses[0], witnesses[1:]...)
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
			pk := &ecelgamalcommitment.PublicKey{
				G: g,
				H: h,
			}
			scheme := ecelgamalcommitment.NewScheme(pk)

			messageA, err := curve.Random(prng)
			require.NoError(t, err)
			messageB, err := curve.Random(prng)
			require.NoError(t, err)
			messageAMinusB := messageA.Sub(messageB)

			commitmentA, witnessA, err := scheme.Commit(messageA, prng)
			require.NoError(t, err)
			commitmentB, witnessB, err := scheme.Commit(messageB, prng)
			require.NoError(t, err)

			aMinusBCommitment := scheme.CommitmentSub(commitmentA, commitmentB)
			aMinusBWitness := scheme.OpeningSub(witnessA, witnessB)

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
			pk := &ecelgamalcommitment.PublicKey{
				G: g,
				H: h,
			}
			scheme := ecelgamalcommitment.NewScheme(pk)

			message, err := curve.Random(prng)
			require.NoError(t, err)
			messageNeg := message.Neg()

			commitment, witness, err := scheme.Commit(message, prng)
			require.NoError(t, err)

			negCommitment := scheme.CommitmentNeg(commitment)
			negWitness := scheme.OpeningNeg(witness)
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
			pk := &ecelgamalcommitment.PublicKey{
				G: g,
				H: h,
			}
			scheme := ecelgamalcommitment.NewScheme(pk)

			message, err := curve.Random(prng)
			require.NoError(t, err)
			sc, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			scaledMessage := message.ScalarMul(sc)

			commitment, witness, err := scheme.Commit(message, prng)
			require.NoError(t, err)

			scaledCommitment := scheme.CommitmentScale(commitment, sc)
			scaledWitness := scheme.OpeningScale(witness, sc)
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
			pk := &ecelgamalcommitment.PublicKey{
				G: g,
				H: h,
			}
			scheme := ecelgamalcommitment.NewScheme(pk)

			messageA, err := curve.Random(prng)
			require.NoError(t, err)
			messageB, err := curve.Random(prng)
			require.NoError(t, err)
			messageAPlusB := messageA.Add(messageB)

			commitmentA, witnessA, err := scheme.Commit(messageA, prng)
			require.NoError(t, err)
			commitmentB, witnessB, err := scheme.Commit(messageB, prng)
			require.NoError(t, err)
			commitmentBPrime, witnessBPrime, err := scheme.Commit(messageB, prng)
			require.NoError(t, err)

			commitmentAPlusB := scheme.CommitmentAdd(commitmentA, commitmentB)
			commitmentAPlusBPrime := scheme.CommitmentAdd(commitmentA, commitmentBPrime)
			witnessAPlusB := scheme.OpeningAdd(witnessA, witnessB)
			witnessAPlusBPrime := scheme.OpeningAdd(witnessA, witnessBPrime)

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
			pk := &ecelgamalcommitment.PublicKey{
				G: g,
				H: h,
			}
			scheme := ecelgamalcommitment.NewScheme(pk)

			message, err := curve.Random(prng)
			require.NoError(t, err)
			scale, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			scaledMessage := message.ScalarMul(scale)

			commitmentA, witnessA, err := scheme.Commit(message, prng)
			require.NoError(t, err)
			commitmentB, witnessB, err := scheme.Commit(message, prng)
			require.NoError(t, err)

			commitmentAScaled := scheme.CommitmentScale(commitmentA, scale)
			commitmentBScaled := scheme.CommitmentScale(commitmentB, scale)

			openingAScaled := scheme.OpeningScale(witnessA, scale)
			openingBScaled := scheme.OpeningScale(witnessB, scale)

			err = scheme.Verify(scaledMessage, commitmentAScaled, openingBScaled)
			require.Error(t, err)

			err = scheme.Verify(scaledMessage, commitmentBScaled, openingAScaled)
			require.Error(t, err)
		})
	}
}
