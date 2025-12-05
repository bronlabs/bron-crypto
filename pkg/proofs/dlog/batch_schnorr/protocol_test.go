package batch_schnorr_test

import (
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/mathutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/batch_schnorr"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testHappyPath(t, curve)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		testHappyPath(t, curve)
	})
	t.Run("edwards25519", func(t *testing.T) {
		t.Parallel()
		curve := edwards25519.NewPrimeSubGroup()
		testHappyPath(t, curve)
	})
	t.Run("curve25519", func(t *testing.T) {
		t.Parallel()
		curve := curve25519.NewPrimeSubGroup()
		testHappyPath(t, curve)
	})
	t.Run("pallas", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewPallasCurve()
		testHappyPath(t, curve)
	})
	t.Run("vesta", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewVestaCurve()
		testHappyPath(t, curve)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1()
		testHappyPath(t, curve)
	})
	t.Run("bls12381g2", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG2()
		testHappyPath(t, curve)
	})
}

func Test_Simulator(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testSimulator(t, curve)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		testSimulator(t, curve)
	})
	t.Run("edwards25519", func(t *testing.T) {
		t.Parallel()
		curve := edwards25519.NewPrimeSubGroup()
		testSimulator(t, curve)
	})
	t.Run("curve25519", func(t *testing.T) {
		t.Parallel()
		curve := curve25519.NewPrimeSubGroup()
		testSimulator(t, curve)
	})
	t.Run("pallas", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewPallasCurve()
		testSimulator(t, curve)
	})
	t.Run("vesta", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewVestaCurve()
		testSimulator(t, curve)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1()
		testSimulator(t, curve)
	})
	t.Run("bls12381g2", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG2()
		testSimulator(t, curve)
	})
}

func testHappyPath[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](tb testing.TB, group algebra.PrimeGroup[G, S]) {
	tb.Helper()

	prng := crand.Reader
	k, err := mathutils.RandomUint64(prng)
	require.NoError(tb, err)
	k = k%128 + 2

	generator, err := group.Random(crand.Reader)
	require.NoError(tb, err)

	protocol, err := batch_schnorr.NewProtocol(int(k), group, prng)
	require.NoError(tb, err)

	sf, ok := group.ScalarStructure().(algebra.PrimeField[S])
	require.True(tb, ok)

	ws := make([]S, k)
	for i := range k {
		ws[i], err = sf.Random(crand.Reader)
		require.NoError(tb, err)
	}
	xs := make([]G, k)
	for i := range k {
		xs[i] = generator.ScalarOp(ws[i])
	}

	witness := batch_schnorr.NewWitness(ws...)
	statement := batch_schnorr.NewStatement(generator, xs...)

	// round 1
	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(tb, err)

	// round 2
	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(tb, err)

	// round 3
	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(tb, err)

	// verify
	err = protocol.Verify(statement, commitment, challenge, response)
	require.NoError(tb, err)
}

func testSimulator[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](tb testing.TB, group algebra.PrimeGroup[G, S]) {
	tb.Helper()

	prng := crand.Reader
	k, err := mathutils.RandomUint64(prng)
	require.NoError(tb, err)
	k = k%128 + 2

	generator, err := group.Random(crand.Reader)
	require.NoError(tb, err)

	protocol, err := batch_schnorr.NewProtocol(int(k), group, crand.Reader)
	require.NoError(tb, err)

	xs := make([]G, k)
	for i := range k {
		xs[i], err = group.Random(prng)
		require.NoError(tb, err)
	}
	statement := batch_schnorr.NewStatement(generator, xs...)

	// simulate
	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(tb, err)
	commitment, response, err := protocol.RunSimulator(statement, challenge)
	require.NoError(tb, err)

	// verify
	err = protocol.Verify(statement, commitment, challenge, response)
	require.NoError(tb, err)
}
