package vpedersencomm_test

import (
	crand "crypto/rand"
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	pedersenvectorcommitment "github.com/copperexchange/krypton-primitives/pkg/vector_commitments/pedersen"
	"github.com/stretchr/testify/require"
	"io"
	"testing"
)

const vectorLength = 16

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

			gs, h := randomParams(t, curve, prng)
			scheme := pedersenvectorcommitment.NewScheme(gs, h)

			message := randomVector(t, curve, prng)
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

			gs, h := randomParams(t, curve, prng)
			scheme := pedersenvectorcommitment.NewScheme(gs, h)

			message := randomVector(t, curve, prng)

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

			gs, h := randomParams(t, curve, prng)
			scheme := pedersenvectorcommitment.NewScheme(gs, h)

			message := randomVector(t, curve, prng)

			_, opening, err := scheme.Commit(message, prng)
			require.NoError(t, err)

			err = scheme.Verify(message, nil, opening)
			require.Error(t, err)
		})
	}
}

func randomParams(t require.TestingT, curve curves.Curve, prng io.Reader) ([]curves.Point, curves.Point) {
	gs := make([]curves.Point, vectorLength)
	for i := range gs {
		var err error
		gs[i], err = curve.Random(prng)
		require.NoError(t, err)
	}
	h, err := curve.Random(prng)
	require.NoError(t, err)

	return gs, h
}

func randomVector(t require.TestingT, curve curves.Curve, prng io.Reader) []pedersenvectorcommitment.Element {
	v := make([]curves.Scalar, vectorLength)
	for i := range v {
		var err error
		v[i], err = curve.ScalarField().Random(prng)
		require.NoError(t, err)
	}

	return v
}
