package pedersen_comm_test

import (
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/p256"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/pasta"
	"github.com/bronlabs/krypton-primitives/pkg/commitments/pedersen"
)

func Test_ValidCommitment(t *testing.T) {
	t.Parallel()

	supportedCurves := []curves.Curve{
		p256.NewCurve(),
		k256.NewCurve(),
		edwards25519.NewCurve(),
		pasta.NewPallasCurve(),
		pasta.NewVestaCurve(),
		bls12381.NewG1(),
		bls12381.NewG2(),
	}
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()
			ck := randomCk(t, curve, prng)
			m := randomMessage(t, curve, prng)

			c, r, err := ck.Commit(m, prng)
			require.NoError(t, err)

			err = ck.Verify(c, m, r)
			require.NoError(t, err)
		})
	}
}

func Test_InvalidCommitment(t *testing.T) {
	t.Parallel()

	supportedCurves := []curves.Curve{
		p256.NewCurve(),
		k256.NewCurve(),
		edwards25519.NewCurve(),
		pasta.NewPallasCurve(),
		pasta.NewVestaCurve(),
		bls12381.NewG1(),
		bls12381.NewG2(),
	}
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()
			ck := randomCk(t, curve, prng)
			m := randomMessage(t, curve, prng)
			invalidCk := randomCk(t, curve, prng)
			invalidM := randomMessage(t, curve, prng)

			c, r, err := ck.Commit(m, prng)
			require.NoError(t, err)

			err = ck.Verify(c, m, r)
			require.NoError(t, err)

			invalidC, invalidR, err := invalidCk.Commit(invalidM, prng)
			require.NoError(t, err)

			err = invalidCk.Verify(c, m, r)
			require.Error(t, err)
			err = ck.Verify(invalidC, m, r)
			require.Error(t, err)
			err = ck.Verify(c, invalidM, r)
			require.Error(t, err)
			err = ck.Verify(c, m, invalidR)
			require.Error(t, err)
			err = ck.Verify(c, invalidM, invalidR)
			require.Error(t, err)
		})
	}
}

func Test_HomomorphicAdd(t *testing.T) {
	t.Parallel()

	supportedCurves := []curves.Curve{
		p256.NewCurve(),
		k256.NewCurve(),
		edwards25519.NewCurve(),
		pasta.NewPallasCurve(),
		pasta.NewVestaCurve(),
		bls12381.NewG1(),
		bls12381.NewG2(),
	}
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()
			ck := randomCk(t, curve, prng)
			m1 := randomMessage(t, curve, prng)
			m2 := randomMessage(t, curve, prng)
			m := m1.Add(m2)

			c1, r1, err := ck.Commit(m1, prng)
			require.NoError(t, err)
			c2, r2, err := ck.Commit(m2, prng)
			require.NoError(t, err)

			c, err := ck.CommitmentAdd(c1, c2)
			require.NoError(t, err)
			r, err := ck.WitnessAdd(r1, r2)
			require.NoError(t, err)

			err = ck.Verify(c, m, r)
			require.NoError(t, err)
		})
	}
}

func Test_HomomorphicAddMessage(t *testing.T) {
	t.Parallel()

	supportedCurves := []curves.Curve{
		p256.NewCurve(),
		k256.NewCurve(),
		edwards25519.NewCurve(),
		pasta.NewPallasCurve(),
		pasta.NewVestaCurve(),
		bls12381.NewG1(),
		bls12381.NewG2(),
	}
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()
			ck := randomCk(t, curve, prng)
			m1 := randomMessage(t, curve, prng)
			m2 := randomMessage(t, curve, prng)
			m := m1.Add(m2)

			c1, r, err := ck.Commit(m1, prng)
			require.NoError(t, err)

			c, err := ck.CommitmentAddMessage(c1, m2)
			require.NoError(t, err)

			err = ck.Verify(c, m, r)
			require.NoError(t, err)
		})
	}
}

func Test_HomomorphicSub(t *testing.T) {
	t.Parallel()

	supportedCurves := []curves.Curve{
		p256.NewCurve(),
		k256.NewCurve(),
		edwards25519.NewCurve(),
		pasta.NewPallasCurve(),
		pasta.NewVestaCurve(),
		bls12381.NewG1(),
		bls12381.NewG2(),
	}
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()
			ck := randomCk(t, curve, prng)
			m1 := randomMessage(t, curve, prng)
			m2 := randomMessage(t, curve, prng)
			m := m1.Sub(m2)

			c1, r1, err := ck.Commit(m1, prng)
			require.NoError(t, err)
			c2, r2, err := ck.Commit(m2, prng)
			require.NoError(t, err)

			c, err := ck.CommitmentSub(c1, c2)
			require.NoError(t, err)
			r, err := ck.WitnessSub(r1, r2)
			require.NoError(t, err)

			err = ck.Verify(c, m, r)
			require.NoError(t, err)
		})
	}
}

func Test_HomomorphicSubMessage(t *testing.T) {
	t.Parallel()

	supportedCurves := []curves.Curve{
		p256.NewCurve(),
		k256.NewCurve(),
		edwards25519.NewCurve(),
		pasta.NewPallasCurve(),
		pasta.NewVestaCurve(),
		bls12381.NewG1(),
		bls12381.NewG2(),
	}
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()
			ck := randomCk(t, curve, prng)
			m1 := randomMessage(t, curve, prng)
			m2 := randomMessage(t, curve, prng)
			m := m1.Sub(m2)

			c1, r, err := ck.Commit(m1, prng)
			require.NoError(t, err)

			c, err := ck.CommitmentSubMessage(c1, m2)
			require.NoError(t, err)

			err = ck.Verify(c, m, r)
			require.NoError(t, err)
		})
	}
}

func Test_HomomorphicMul(t *testing.T) {
	t.Parallel()

	supportedCurves := []curves.Curve{
		p256.NewCurve(),
		k256.NewCurve(),
		edwards25519.NewCurve(),
		pasta.NewPallasCurve(),
		pasta.NewVestaCurve(),
		bls12381.NewG1(),
		bls12381.NewG2(),
	}
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()
			ck := randomCk(t, curve, prng)
			m1 := randomMessage(t, curve, prng)
			m2 := randomMessage(t, curve, prng)
			m := m1.Mul(m2)

			c1, r1, err := ck.Commit(m1, prng)
			require.NoError(t, err)

			c, err := ck.CommitmentMul(c1, m2)
			require.NoError(t, err)
			r, err := ck.WitnessMul(r1, m2)
			require.NoError(t, err)

			err = ck.Verify(c, m, r)
			require.NoError(t, err)
		})
	}
}

func Test_HomomorphicNeg(t *testing.T) {
	t.Parallel()

	supportedCurves := []curves.Curve{
		p256.NewCurve(),
		k256.NewCurve(),
		edwards25519.NewCurve(),
		pasta.NewPallasCurve(),
		pasta.NewVestaCurve(),
		bls12381.NewG1(),
		bls12381.NewG2(),
	}
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()
			ck := randomCk(t, curve, prng)
			m1 := randomMessage(t, curve, prng)
			m := m1.Neg()

			c1, r1, err := ck.Commit(m1, prng)
			require.NoError(t, err)

			c, err := ck.CommitmentNeg(c1)
			require.NoError(t, err)
			r, err := ck.WitnessNeg(r1)
			require.NoError(t, err)

			err = ck.Verify(c, m, r)
			require.NoError(t, err)
		})
	}
}

func randomCk(tb testing.TB, curve curves.Curve, prng io.Reader) *pedersen_comm.CommittingKey {
	tb.Helper()

	g, err := curve.Random(prng)
	require.NoError(tb, err)
	h, err := curve.Random(prng)
	require.NoError(tb, err)

	return pedersen_comm.NewCommittingKey(g, h)
}

func randomMessage(tb testing.TB, curve curves.Curve, prng io.Reader) pedersen_comm.Message {
	tb.Helper()

	s, err := curve.ScalarField().Random(prng)
	require.NoError(tb, err)
	return s
}
