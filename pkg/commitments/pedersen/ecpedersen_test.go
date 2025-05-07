package pedersen_comm_test

import (
	crand "crypto/rand"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
)

func Test_ValidCommitment(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testValidCommitment(t, curve)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		testValidCommitment(t, curve)
	})
	t.Run("edwards25519", func(t *testing.T) {
		t.Parallel()
		curve := edwards25519.NewCurve()
		testValidCommitment(t, curve)
	})
	t.Run("pallas", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewPallasCurve()
		testValidCommitment(t, curve)
	})
	t.Run("vesta", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewVestaCurve()
		testValidCommitment(t, curve)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1Curve()
		testValidCommitment(t, curve)
	})
	t.Run("bls12381g2", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG2Curve()
		testValidCommitment(t, curve)
	})
}

func Test_InvalidCommitment(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testInvalidCommitment(t, curve)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		testInvalidCommitment(t, curve)
	})
	t.Run("edwards25519", func(t *testing.T) {
		t.Parallel()
		curve := edwards25519.NewCurve()
		testInvalidCommitment(t, curve)
	})
	t.Run("pallas", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewPallasCurve()
		testInvalidCommitment(t, curve)
	})
	t.Run("vesta", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewVestaCurve()
		testInvalidCommitment(t, curve)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1Curve()
		testInvalidCommitment(t, curve)
	})
	t.Run("bls12381g2", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG2Curve()
		testInvalidCommitment(t, curve)
	})
}

func Test_HomomorphicAdd(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testHomomorphicAdd(t, curve)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		testHomomorphicAdd(t, curve)
	})
	t.Run("edwards25519", func(t *testing.T) {
		t.Parallel()
		curve := edwards25519.NewCurve()
		testHomomorphicAdd(t, curve)
	})
	t.Run("pallas", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewPallasCurve()
		testHomomorphicAdd(t, curve)
	})
	t.Run("vesta", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewVestaCurve()
		testHomomorphicAdd(t, curve)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1Curve()
		testHomomorphicAdd(t, curve)
	})
	t.Run("bls12381g2", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG2Curve()
		testHomomorphicAdd(t, curve)
	})
}

func Test_HomomorphicAddMessage(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testHomomorphicAddMessage(t, curve)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		testHomomorphicAddMessage(t, curve)
	})
	t.Run("edwards25519", func(t *testing.T) {
		t.Parallel()
		curve := edwards25519.NewCurve()
		testHomomorphicAddMessage(t, curve)
	})
	t.Run("pallas", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewPallasCurve()
		testHomomorphicAddMessage(t, curve)
	})
	t.Run("vesta", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewVestaCurve()
		testHomomorphicAddMessage(t, curve)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1Curve()
		testHomomorphicAddMessage(t, curve)
	})
	t.Run("bls12381g2", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG2Curve()
		testHomomorphicAddMessage(t, curve)
	})
}

func Test_HomomorphicSub(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testHomomorphicSub(t, curve)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		testHomomorphicSub(t, curve)
	})
	t.Run("edwards25519", func(t *testing.T) {
		t.Parallel()
		curve := edwards25519.NewCurve()
		testHomomorphicSub(t, curve)
	})
	t.Run("pallas", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewPallasCurve()
		testHomomorphicSub(t, curve)
	})
	t.Run("vesta", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewVestaCurve()
		testHomomorphicSub(t, curve)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1Curve()
		testHomomorphicSub(t, curve)
	})
	t.Run("bls12381g2", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG2Curve()
		testHomomorphicSub(t, curve)
	})
}

func Test_HomomorphicSubMessage(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testHomomorphicSubMessage(t, curve)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		testHomomorphicSubMessage(t, curve)
	})
	t.Run("edwards25519", func(t *testing.T) {
		t.Parallel()
		curve := edwards25519.NewCurve()
		testHomomorphicSubMessage(t, curve)
	})
	t.Run("pallas", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewPallasCurve()
		testHomomorphicSubMessage(t, curve)
	})
	t.Run("vesta", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewVestaCurve()
		testHomomorphicSubMessage(t, curve)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1Curve()
		testHomomorphicSubMessage(t, curve)
	})
	t.Run("bls12381g2", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG2Curve()
		testHomomorphicSubMessage(t, curve)
	})
}

func Test_HomomorphicMul(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testHomomorphicMul(t, curve)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		testHomomorphicMul(t, curve)
	})
	t.Run("edwards25519", func(t *testing.T) {
		t.Parallel()
		curve := edwards25519.NewCurve()
		testHomomorphicMul(t, curve)
	})
	t.Run("pallas", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewPallasCurve()
		testHomomorphicMul(t, curve)
	})
	t.Run("vesta", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewVestaCurve()
		testHomomorphicMul(t, curve)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1Curve()
		testHomomorphicMul(t, curve)
	})
	t.Run("bls12381g2", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG2Curve()
		testHomomorphicMul(t, curve)
	})
}

func Test_HomomorphicNeg(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testHomomorphicNeg(t, curve)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		testHomomorphicNeg(t, curve)
	})
	t.Run("edwards25519", func(t *testing.T) {
		t.Parallel()
		curve := edwards25519.NewCurve()
		testHomomorphicNeg(t, curve)
	})
	t.Run("pallas", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewPallasCurve()
		testHomomorphicNeg(t, curve)
	})
	t.Run("vesta", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewVestaCurve()
		testHomomorphicNeg(t, curve)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1Curve()
		testHomomorphicNeg(t, curve)
	})
	t.Run("bls12381g2", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG2Curve()
		testHomomorphicNeg(t, curve)
	})
}

func testValidCommitment[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](t *testing.T, curve C) {
	t.Helper()

	prng := crand.Reader
	ck := randomCk(t, curve, prng)
	m := randomMessage(t, curve, prng)

	c, r, err := ck.Commit(m, prng)
	require.NoError(t, err)

	err = ck.Verify(c, m, r)
	require.NoError(t, err)
}

func testInvalidCommitment[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](t *testing.T, curve C) {
	t.Helper()

	prng := crand.Reader

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
}

func testHomomorphicAdd[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](t *testing.T, curve C) {
	t.Helper()
	prng := crand.Reader

	ck := randomCk(t, curve, prng)
	m1 := randomMessage(t, curve, prng)
	m2 := randomMessage(t, curve, prng)
	m, err := ck.MessageAdd(m1, m2)
	require.NoError(t, err)

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
}

func testHomomorphicAddMessage[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](t *testing.T, curve C) {
	t.Helper()
	prng := crand.Reader

	ck := randomCk(t, curve, prng)
	m1 := randomMessage(t, curve, prng)
	m2 := randomMessage(t, curve, prng)
	m, err := ck.MessageAdd(m1, m2)
	require.NoError(t, err)

	c1, r, err := ck.Commit(m1, prng)
	require.NoError(t, err)

	c, err := ck.CommitmentAddMessage(c1, m2)
	require.NoError(t, err)

	err = ck.Verify(c, m, r)
	require.NoError(t, err)
}

func testHomomorphicSub[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](t *testing.T, curve C) {
	t.Helper()
	prng := crand.Reader

	ck := randomCk(t, curve, prng)
	m1 := randomMessage(t, curve, prng)
	m2 := randomMessage(t, curve, prng)
	m, err := ck.MessageSub(m1, m2)
	require.NoError(t, err)

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
}

func testHomomorphicSubMessage[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](t *testing.T, curve C) {
	t.Helper()
	prng := crand.Reader

	ck := randomCk(t, curve, prng)
	m1 := randomMessage(t, curve, prng)
	m2 := randomMessage(t, curve, prng)
	m, err := ck.MessageSub(m1, m2)

	c1, r, err := ck.Commit(m1, prng)
	require.NoError(t, err)

	c, err := ck.CommitmentSubMessage(c1, m2)
	require.NoError(t, err)

	err = ck.Verify(c, m, r)
	require.NoError(t, err)
}

func testHomomorphicMul[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](t *testing.T, curve C) {
	t.Helper()
	prng := crand.Reader

	ck := randomCk(t, curve, prng)
	m1 := randomMessage(t, curve, prng)
	m2 := randomMessage(t, curve, prng)
	m, err := ck.MessageMul(m1, m2.M)
	require.NoError(t, err)

	c1, r1, err := ck.Commit(m1, prng)
	require.NoError(t, err)

	c, err := ck.CommitmentMul(c1, m2.M)
	require.NoError(t, err)
	r, err := ck.WitnessMul(r1, m2.M)
	require.NoError(t, err)

	err = ck.Verify(c, m, r)
	require.NoError(t, err)
}

func testHomomorphicNeg[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](t *testing.T, curve C) {
	t.Helper()
	prng := crand.Reader

	ck := randomCk(t, curve, prng)
	m1 := randomMessage(t, curve, prng)
	m, err := ck.MessageNeg(m1)
	require.NoError(t, err)

	c1, r1, err := ck.Commit(m1, prng)
	require.NoError(t, err)

	c, err := ck.CommitmentNeg(c1)
	require.NoError(t, err)
	r, err := ck.WitnessNeg(r1)
	require.NoError(t, err)

	err = ck.Verify(c, m, r)
	require.NoError(t, err)
}

func randomCk[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](tb testing.TB, curve C, prng io.Reader) *pedersen_comm.CommittingKey[P, F, S] {
	tb.Helper()

	g, err := curve.Random(prng)
	require.NoError(tb, err)
	h, err := curve.Random(prng)
	require.NoError(tb, err)

	return pedersen_comm.NewCommittingKey(g, h)
}

func randomMessage[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](tb testing.TB, curve C, prng io.Reader) *pedersen_comm.Message[S] {
	tb.Helper()

	s, err := curve.ScalarField().Random(prng)
	require.NoError(tb, err)
	return pedersen_comm.NewMessage(s)
}
