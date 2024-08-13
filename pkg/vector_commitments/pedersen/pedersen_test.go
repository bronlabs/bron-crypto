package pedersenvectorcommitments_test

//import (
//	crand "crypto/rand"
//	"testing"
//
//	"github.com/stretchr/testify/require"
//
//	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
//	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
//	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
//	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
//	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
//	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
//	pedersenvectorcommitments "github.com/copperexchange/krypton-primitives/pkg/vector_commitments/pedersen"
//)
//
//var supportedCurves = []curves.Curve{
//	k256.NewCurve(),
//	p256.NewCurve(),
//	pallas.NewCurve(),
//	edwards25519.NewCurve(),
//	bls12381.NewG1(),
//	bls12381.NewG2(),
//}
//
//func TestHappyPathCommitment(t *testing.T) {
//	t.Parallel()
//
//	sessionId := []byte("happyPathCommitmentSessionId")
//	prng := crand.Reader
//
//	for i, curve := range supportedCurves {
//		t.Run(curve.Name(), func(t *testing.T) {
//			t.Parallel()
//
//			committer, err := pedersenvectorcommitments.NewVectorCommitter(sessionId, curve, uint(i+1), prng)
//			require.NoError(t, err)
//			require.NotNil(t, committer)
//
//			verifier, err := pedersenvectorcommitments.NewVectorVerifier(sessionId, curve, uint(i+1))
//			require.NoError(t, err)
//			require.NotNil(t, verifier)
//
//			vector := make([]pedersenvectorcommitments.VectorElement, i+1)
//			for j := 0; j <= i; j++ {
//				vector[j], err = curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//			}
//
//			commit, opening, err := committer.Commit(vector)
//			require.NoError(t, err)
//			require.NotNil(t, commit)
//			require.NotNil(t, opening)
//
//			err = verifier.Verify(commit, opening)
//			require.NoError(t, err)
//		})
//	}
//}
//
//func TestShouldFailOnInvalidCommitmentOrOpening(t *testing.T) {
//	t.Parallel()
//
//	sessionId := []byte("happyPathCommitmentSessionId")
//	prng := crand.Reader
//
//	for i, curve := range supportedCurves {
//		t.Run(curve.Name(), func(t *testing.T) {
//			t.Parallel()
//
//			committer, err := pedersenvectorcommitments.NewVectorCommitter(sessionId, curve, uint(i+1), prng)
//			require.NoError(t, err)
//			require.NotNil(t, committer)
//
//			verifier, err := pedersenvectorcommitments.NewVectorVerifier(sessionId, curve, uint(i+1))
//			require.NoError(t, err)
//			require.NotNil(t, verifier)
//
//			vector := make([]pedersenvectorcommitments.VectorElement, i+1)
//			for j := 0; j <= i; j++ {
//				vector[j], err = curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//			}
//
//			commitmentA, openingA, err := committer.Commit(vector)
//			require.NoError(t, err)
//			commitmentB, openingB, err := committer.Commit(vector)
//			require.NoError(t, err)
//
//			err = verifier.Verify(commitmentA, openingB)
//			require.Error(t, err)
//
//			err = verifier.Verify(commitmentB, openingA)
//			require.Error(t, err)
//		})
//	}
//}
//
//func TestShouldFailOnNilCommitment(t *testing.T) {
//	t.Parallel()
//
//	sessionId := []byte("shouldFailOnNilCommitmentSessionId")
//	prng := crand.Reader
//
//	for i, curve := range supportedCurves {
//		t.Run(curve.Name(), func(t *testing.T) {
//			t.Parallel()
//
//			committer, err := pedersenvectorcommitments.NewVectorCommitter(sessionId, curve, uint(i+1), prng)
//			require.NoError(t, err)
//			require.NotNil(t, committer)
//
//			verifier, err := pedersenvectorcommitments.NewVectorVerifier(sessionId, curve, uint(i+1))
//			require.NoError(t, err)
//			require.NotNil(t, verifier)
//
//			vector := make([]pedersenvectorcommitments.VectorElement, i+1)
//			for j := 0; j <= i; j++ {
//				vector[j], err = curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//			}
//
//			_, opening, err := committer.Commit(vector)
//			require.NoError(t, err)
//
//			err = verifier.Verify(nil, opening)
//			require.Error(t, err)
//		})
//	}
//}
//
//func TestHappyPathCombine(t *testing.T) {
//	t.Parallel()
//
//	sessionId := []byte("happyPathCombineSessionId")
//	prng := crand.Reader
//
//	for i, curve := range supportedCurves {
//		t.Run(curve.Name(), func(t *testing.T) {
//			t.Parallel()
//
//			committer, err := pedersenvectorcommitments.NewVectorCommitter(sessionId, curve, uint(i+1), prng)
//			require.NoError(t, err)
//			require.NotNil(t, committer)
//
//			verifier, err := pedersenvectorcommitments.NewVectorVerifier(sessionId, curve, uint(i+1))
//			require.NoError(t, err)
//			require.NotNil(t, verifier)
//
//			vectorA := make([]pedersenvectorcommitments.VectorElement, i+1)
//			vectorB := make([]pedersenvectorcommitments.VectorElement, i+1)
//			vectorAplusB := make([]pedersenvectorcommitments.VectorElement, i+1)
//			for j := 0; j <= i; j++ {
//				vectorA[j], err = curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//				vectorB[j], err = curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//				vectorAplusB[j] = vectorA[j].Add(vectorB[j])
//			}
//
//			commitmentA, openingA, err := committer.Commit(vectorA)
//			require.NoError(t, err)
//			commitmentB, openingB, err := committer.Commit(vectorB)
//			require.NoError(t, err)
//
//			commitmentAPlusB, err := verifier.CombineCommitments(commitmentA, commitmentB)
//			require.NoError(t, err)
//			openingAPlusB, err := verifier.CombineOpenings(openingA, openingB)
//			require.NoError(t, err)
//
//			err = verifier.Verify(commitmentAPlusB, openingAPlusB)
//			require.NoError(t, err)
//		})
//	}
//}
//
//func TestOpenOnWrongCombine(t *testing.T) {
//	t.Parallel()
//
//	sessionId := []byte("happyPathCombineSessionId")
//	prng := crand.Reader
//
//	for i, curve := range supportedCurves {
//		t.Run(curve.Name(), func(t *testing.T) {
//			t.Parallel()
//
//			committer, err := pedersenvectorcommitments.NewVectorCommitter(sessionId, curve, uint(i+1), prng)
//			require.NoError(t, err)
//			require.NotNil(t, committer)
//
//			verifier, err := pedersenvectorcommitments.NewVectorVerifier(sessionId, curve, uint(i+1))
//			require.NoError(t, err)
//			require.NotNil(t, verifier)
//
//			vectorA := make([]pedersenvectorcommitments.VectorElement, i+1)
//			vectorB := make([]pedersenvectorcommitments.VectorElement, i+1)
//			vectorAplusB := make([]pedersenvectorcommitments.VectorElement, i+1)
//			for j := 0; j <= i; j++ {
//				vectorA[j], err = curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//				vectorB[j], err = curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//				vectorAplusB[j] = vectorA[j].Add(vectorB[j])
//			}
//
//			commitmentA, openingA, err := committer.Commit(vectorA)
//			require.NoError(t, err)
//			commitmentB, openingB, err := committer.Commit(vectorB)
//			require.NoError(t, err)
//			commitmentBPrime, openingBPrime, err := committer.Commit(vectorB)
//			require.NoError(t, err)
//
//			commitmentAPlusB, err := verifier.CombineCommitments(commitmentA, commitmentB)
//			require.NoError(t, err)
//			commitmentAPlusBPrime, err := verifier.CombineCommitments(commitmentA, commitmentBPrime)
//			require.NoError(t, err)
//			openingAPlusB, err := verifier.CombineOpenings(openingA, openingB)
//			require.NoError(t, err)
//			openingAPlusBPrime, err := verifier.CombineOpenings(openingA, openingBPrime)
//			require.NoError(t, err)
//
//			err = verifier.Verify(commitmentAPlusB, openingAPlusBPrime)
//			require.Error(t, err)
//
//			err = verifier.Verify(commitmentAPlusBPrime, openingAPlusB)
//			require.Error(t, err)
//		})
//	}
//}
//
//func TestHappyPathScale(t *testing.T) {
//	t.Parallel()
//
//	sessionId := []byte("happyPathScaleSessionId")
//	prng := crand.Reader
//
//	for i, curve := range supportedCurves {
//		t.Run(curve.Name(), func(t *testing.T) {
//			t.Parallel()
//
//			committer, err := pedersenvectorcommitments.NewVectorCommitter(sessionId, curve, uint(i+1), prng)
//			require.NoError(t, err)
//			require.NotNil(t, committer)
//
//			verifier, err := pedersenvectorcommitments.NewVectorVerifier(sessionId, curve, uint(i+1))
//			require.NoError(t, err)
//			require.NotNil(t, verifier)
//
//			vector := make([]pedersenvectorcommitments.VectorElement, i+1)
//			for j := 0; j <= i; j++ {
//				vector[j], err = curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//			}
//			scale, err := curve.ScalarField().Random(prng)
//			require.NoError(t, err)
//
//			commitment, opening, err := committer.Commit(vector)
//			require.NoError(t, err)
//			require.NotNil(t, commitment)
//			require.NotNil(t, opening)
//
//			scaledCommitment, err := verifier.ScaleCommitment(commitment, scale.Nat())
//			require.NoError(t, err)
//
//			scaledOpening, err := verifier.ScaleOpening(opening, scale.Nat())
//			require.NoError(t, err)
//
//			err = verifier.Verify(scaledCommitment, scaledOpening)
//			require.NoError(t, err)
//		})
//	}
//}
//
//func TestWrongScale(t *testing.T) {
//	t.Parallel()
//
//	sessionId := []byte("happyPathScaleSessionId")
//	prng := crand.Reader
//
//	for i, curve := range supportedCurves {
//		t.Run(curve.Name(), func(t *testing.T) {
//			t.Parallel()
//
//			committer, err := pedersenvectorcommitments.NewVectorCommitter(sessionId, curve, uint(i+1), prng)
//			require.NoError(t, err)
//			require.NotNil(t, committer)
//
//			verifier, err := pedersenvectorcommitments.NewVectorVerifier(sessionId, curve, uint(i+1))
//			require.NoError(t, err)
//			require.NotNil(t, verifier)
//
//			vectorA := make([]pedersenvectorcommitments.VectorElement, i+1)
//			vectorB := make([]pedersenvectorcommitments.VectorElement, i+1)
//			for j := 0; j <= i; j++ {
//				vectorA[j], err = curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//				vectorB[j], err = curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//			}
//			scale, err := curve.ScalarField().Random(prng)
//			require.NoError(t, err)
//
//			commitmentA, openingA, err := committer.Commit(vectorA)
//			require.NoError(t, err)
//			require.NotNil(t, commitmentA)
//			require.NotNil(t, openingA)
//			commitmentB, openingB, err := committer.Commit(vectorB)
//			require.NoError(t, err)
//			require.NotNil(t, commitmentB)
//			require.NotNil(t, openingB)
//
//			scaledCommitmentA, err := verifier.ScaleCommitment(commitmentA, scale.Nat())
//			require.NoError(t, err)
//			scaledCommitmentB, err := verifier.ScaleCommitment(commitmentB, scale.Nat())
//			require.NoError(t, err)
//			scaledOpeningA, err := verifier.ScaleOpening(openingA, scale.Nat())
//			require.NoError(t, err)
//			scaledOpeningB, err := verifier.ScaleOpening(openingB, scale.Nat())
//			require.NoError(t, err)
//
//			err = verifier.Verify(scaledCommitmentA, scaledOpeningB)
//			require.Error(t, err)
//
//			err = verifier.Verify(scaledCommitmentB, scaledOpeningA)
//			require.Error(t, err)
//		})
//	}
//}
