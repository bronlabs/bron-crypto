package pedersen_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

type badReader struct{}

func (badReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestNewCommitmentKeyUnchecked(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	g := curve.Generator()
	h, err := curve.Random(pcg.NewRandomised())
	require.NoError(t, err)

	t.Run("nil g rejected", func(t *testing.T) {
		t.Parallel()
		k, err := pedersen.NewCommitmentKeyUnchecked(nil, h)
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("nil h rejected", func(t *testing.T) {
		t.Parallel()
		k, err := pedersen.NewCommitmentKeyUnchecked(g, nil)
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("g == h rejected", func(t *testing.T) {
		t.Parallel()
		k, err := pedersen.NewCommitmentKeyUnchecked(g, g)
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("identity g rejected", func(t *testing.T) {
		t.Parallel()
		identity := curve.OpIdentity()
		k, err := pedersen.NewCommitmentKeyUnchecked(identity, h)
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("identity h rejected", func(t *testing.T) {
		t.Parallel()
		identity := curve.OpIdentity()
		k, err := pedersen.NewCommitmentKeyUnchecked(g, identity)
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("valid generators succeed", func(t *testing.T) {
		t.Parallel()
		k, err := pedersen.NewCommitmentKeyUnchecked(g, h)
		require.NoError(t, err)
		require.NotNil(t, k)
		require.True(t, k.G().Equal(g))
		require.True(t, k.H().Equal(h))
	})
}

func TestSampleCommitmentKey(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()

	t.Run("nil group rejected", func(t *testing.T) {
		t.Parallel()
		k, err := pedersen.SampleCommitmentKey[*k256.Point, *k256.Scalar](nil, pcg.NewRandomised()) //nolint:infertypeargs // nil arg blocks inference
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("nil prng rejected", func(t *testing.T) {
		t.Parallel()
		k, err := pedersen.SampleCommitmentKey(curve, nil)
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("failing reader propagates error", func(t *testing.T) {
		t.Parallel()
		k, err := pedersen.SampleCommitmentKey(curve, badReader{})
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("g equals group generator", func(t *testing.T) {
		t.Parallel()
		k, err := pedersen.SampleCommitmentKey(curve, pcg.NewRandomised())
		require.NoError(t, err)
		require.True(t, k.G().Equal(curve.Generator()))
	})

	t.Run("h is non-identity and distinct from g", func(t *testing.T) {
		t.Parallel()
		k, err := pedersen.SampleCommitmentKey(curve, pcg.NewRandomised())
		require.NoError(t, err)
		require.False(t, k.H().IsOpIdentity())
		require.False(t, k.H().Equal(k.G()))
	})

	t.Run("successive samples produce distinct h", func(t *testing.T) {
		t.Parallel()
		prng := pcg.NewRandomised()
		k1, err := pedersen.SampleCommitmentKey(curve, prng)
		require.NoError(t, err)
		k2, err := pedersen.SampleCommitmentKey(curve, prng)
		require.NoError(t, err)
		require.False(t, k1.H().Equal(k2.H()))
	})
}

func TestExtractCommitmentKey(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	g := curve.Generator()

	t.Run("nil base point rejected", func(t *testing.T) {
		t.Parallel()
		k, err := pedersen.ExtractCommitmentKey[*k256.Point, *k256.Scalar](hagrid.NewTranscript("test"), "label", nil) //nolint:infertypeargs // nil arg blocks inference
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("nil transcript rejected", func(t *testing.T) {
		t.Parallel()
		k, err := pedersen.ExtractCommitmentKey(nil, "label", g)
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("empty label rejected", func(t *testing.T) {
		t.Parallel()
		k, err := pedersen.ExtractCommitmentKey(hagrid.NewTranscript("test"), "", g)
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("g equals supplied base point", func(t *testing.T) {
		t.Parallel()
		k, err := pedersen.ExtractCommitmentKey(hagrid.NewTranscript("test"), "label", g)
		require.NoError(t, err)
		require.True(t, k.G().Equal(g))
	})

	t.Run("h is non-identity and distinct from base point", func(t *testing.T) {
		t.Parallel()
		k, err := pedersen.ExtractCommitmentKey(hagrid.NewTranscript("test"), "label", g)
		require.NoError(t, err)
		require.False(t, k.H().IsOpIdentity())
		require.False(t, k.H().Equal(g))
	})

	t.Run("deterministic on equal transcripts and labels", func(t *testing.T) {
		t.Parallel()
		t1 := hagrid.NewTranscript("test")
		t2 := hagrid.NewTranscript("test")
		t1.AppendBytes("ctx", []byte("payload"))
		t2.AppendBytes("ctx", []byte("payload"))

		k1, err := pedersen.ExtractCommitmentKey(t1, "label", g)
		require.NoError(t, err)
		k2, err := pedersen.ExtractCommitmentKey(t2, "label", g)
		require.NoError(t, err)
		require.True(t, k1.Equal(k2))
	})

	t.Run("different labels yield different h", func(t *testing.T) {
		t.Parallel()
		k1, err := pedersen.ExtractCommitmentKey(hagrid.NewTranscript("test"), "label-a", g)
		require.NoError(t, err)
		k2, err := pedersen.ExtractCommitmentKey(hagrid.NewTranscript("test"), "label-b", g)
		require.NoError(t, err)
		require.False(t, k1.H().Equal(k2.H()))
	})

	t.Run("different transcript states yield different h", func(t *testing.T) {
		t.Parallel()
		t1 := hagrid.NewTranscript("test")
		t2 := hagrid.NewTranscript("test")
		t1.AppendBytes("ctx", []byte("payload-a"))
		t2.AppendBytes("ctx", []byte("payload-b"))

		k1, err := pedersen.ExtractCommitmentKey(t1, "label", g)
		require.NoError(t, err)
		k2, err := pedersen.ExtractCommitmentKey(t2, "label", g)
		require.NoError(t, err)
		require.False(t, k1.H().Equal(k2.H()))
	})
}

func TestNewTrapdoorKey(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	g := curve.Generator()
	field := k256.NewScalarField()
	lambda := field.FromUint64(7)

	t.Run("nil g rejected", func(t *testing.T) {
		t.Parallel()
		tk, err := pedersen.NewTrapdoorKey[*k256.Point, *k256.Scalar](nil, lambda) //nolint:infertypeargs // nil arg blocks inference
		require.Error(t, err)
		require.Nil(t, tk)
	})

	t.Run("nil lambda rejected", func(t *testing.T) {
		t.Parallel()
		tk, err := pedersen.NewTrapdoorKey[*k256.Point, *k256.Scalar](g, nil) //nolint:infertypeargs // nil arg blocks inference
		require.Error(t, err)
		require.Nil(t, tk)
	})

	t.Run("identity g rejected", func(t *testing.T) {
		t.Parallel()
		tk, err := pedersen.NewTrapdoorKey(curve.OpIdentity(), lambda)
		require.Error(t, err)
		require.Nil(t, tk)
	})

	t.Run("zero lambda rejected", func(t *testing.T) {
		t.Parallel()
		tk, err := pedersen.NewTrapdoorKey(g, field.Zero())
		require.Error(t, err)
		require.Nil(t, tk)
	})

	t.Run("one lambda rejected", func(t *testing.T) {
		t.Parallel()
		tk, err := pedersen.NewTrapdoorKey(g, field.One())
		require.Error(t, err)
		require.Nil(t, tk)
	})

	t.Run("h equals g raised to lambda", func(t *testing.T) {
		t.Parallel()
		tk, err := pedersen.NewTrapdoorKey(g, lambda)
		require.NoError(t, err)
		require.True(t, tk.Lambda().Equal(lambda))
		require.True(t, tk.G().Equal(g))
		require.True(t, tk.H().Equal(g.ScalarOp(lambda)),
			"trapdoor key invariant: h must equal g^lambda")
	})
}

func TestSampleTrapdoorKey(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()

	t.Run("nil group rejected", func(t *testing.T) {
		t.Parallel()
		tk, err := pedersen.SampleTrapdoorKey[*k256.Point, *k256.Scalar](nil, pcg.NewRandomised()) //nolint:infertypeargs // nil arg blocks inference
		require.Error(t, err)
		require.Nil(t, tk)
	})

	t.Run("nil prng rejected", func(t *testing.T) {
		t.Parallel()
		tk, err := pedersen.SampleTrapdoorKey(curve, nil)
		require.Error(t, err)
		require.Nil(t, tk)
	})

	t.Run("failing reader propagates error", func(t *testing.T) {
		t.Parallel()
		tk, err := pedersen.SampleTrapdoorKey(curve, badReader{})
		require.Error(t, err)
		require.Nil(t, tk)
	})

	t.Run("g equals group generator and h equals g^lambda", func(t *testing.T) {
		t.Parallel()
		tk, err := pedersen.SampleTrapdoorKey(curve, pcg.NewRandomised())
		require.NoError(t, err)
		require.True(t, tk.G().Equal(curve.Generator()))
		require.True(t, tk.H().Equal(tk.G().ScalarOp(tk.Lambda())),
			"trapdoor key invariant: h must equal g^lambda")
	})

	t.Run("lambda is neither zero nor one", func(t *testing.T) {
		t.Parallel()
		tk, err := pedersen.SampleTrapdoorKey(curve, pcg.NewRandomised())
		require.NoError(t, err)
		require.False(t, tk.Lambda().Equal(field.Zero()))
		require.False(t, tk.Lambda().Equal(field.One()))
	})

	t.Run("successive samples produce distinct trapdoors", func(t *testing.T) {
		t.Parallel()
		prng := pcg.NewRandomised()
		tk1, err := pedersen.SampleTrapdoorKey(curve, prng)
		require.NoError(t, err)
		tk2, err := pedersen.SampleTrapdoorKey(curve, prng)
		require.NoError(t, err)
		require.False(t, tk1.Lambda().Equal(tk2.Lambda()))
	})
}

// TestTrapdoorCommitMatchesCommitmentKeyCommit checks that the trapdoor's optimised
// commitment formula c = (m + lambda*r)*G yields the same commitment as the
// canonical formula c = m*G + r*H. A divergence here would silently break
// soundness of any equivocation argument that swaps between the two paths.
func TestTrapdoorCommitMatchesCommitmentKeyCommit(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()

	tk, err := pedersen.SampleTrapdoorKey(curve, prng)
	require.NoError(t, err)
	ck := tk.Export()

	field := k256.NewScalarField()
	mScalar, err := field.Random(prng)
	require.NoError(t, err)
	message, err := pedersen.NewMessage(mScalar)
	require.NoError(t, err)

	witness, err := tk.SampleWitness(prng)
	require.NoError(t, err)

	cTrapdoor, err := tk.CommitWithWitness(message, witness)
	require.NoError(t, err)
	cKey, err := ck.CommitWithWitness(message, witness)
	require.NoError(t, err)

	require.True(t, cTrapdoor.Equal(cKey),
		"trapdoor (m + lambda*r)*G must equal commitment-key m*G + r*H")
}

// TestHomomorphicMethodsRejectNilArguments checks that every method on the
// Homomorphic interface returns an error (and not a panic) when handed a nil
// pointer argument. Constructor input validation is what anchors the binding
// reduction; a method that silently dereferences nil could let a malformed
// input flow into a fresh zero-valued witness/commitment.
func TestHomomorphicMethodsRejectNilArguments(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()
	field := k256.NewScalarField()

	key, err := pedersen.SampleCommitmentKey(curve, prng)
	require.NoError(t, err)

	witness, err := key.SampleWitness(prng)
	require.NoError(t, err)

	mScalar, err := field.Random(prng)
	require.NoError(t, err)
	message, err := pedersen.NewMessage(mScalar)
	require.NoError(t, err)

	commitment, err := key.CommitWithWitness(message, witness)
	require.NoError(t, err)

	scalar, err := field.Random(prng)
	require.NoError(t, err)

	t.Run("WitnessOp first nil", func(t *testing.T) {
		t.Parallel()
		out, err := key.WitnessOp(nil, witness)
		require.Error(t, err)
		require.Nil(t, out)
	})

	t.Run("WitnessOp second nil", func(t *testing.T) {
		t.Parallel()
		out, err := key.WitnessOp(witness, nil)
		require.Error(t, err)
		require.Nil(t, out)
	})

	t.Run("WitnessOp rest contains nil", func(t *testing.T) {
		t.Parallel()
		out, err := key.WitnessOp(witness, witness, nil)
		require.Error(t, err)
		require.Nil(t, out)
	})

	t.Run("WitnessOpInv nil", func(t *testing.T) {
		t.Parallel()
		out, err := key.WitnessOpInv(nil)
		require.Error(t, err)
		require.Nil(t, out)
	})

	t.Run("WitnessScalarOp nil witness", func(t *testing.T) {
		t.Parallel()
		out, err := key.WitnessScalarOp(nil, scalar)
		require.Error(t, err)
		require.Nil(t, out)
	})

	t.Run("WitnessScalarOp nil scalar", func(t *testing.T) {
		t.Parallel()
		out, err := key.WitnessScalarOp(witness, nil)
		require.Error(t, err)
		require.Nil(t, out)
	})

	t.Run("CommitmentOp first nil", func(t *testing.T) {
		t.Parallel()
		out, err := key.CommitmentOp(nil, commitment)
		require.Error(t, err)
		require.Nil(t, out)
	})

	t.Run("CommitmentOp second nil", func(t *testing.T) {
		t.Parallel()
		out, err := key.CommitmentOp(commitment, nil)
		require.Error(t, err)
		require.Nil(t, out)
	})

	t.Run("CommitmentOp rest contains nil", func(t *testing.T) {
		t.Parallel()
		out, err := key.CommitmentOp(commitment, commitment, nil)
		require.Error(t, err)
		require.Nil(t, out)
	})

	t.Run("CommitmentOpInv nil", func(t *testing.T) {
		t.Parallel()
		out, err := key.CommitmentOpInv(nil)
		require.Error(t, err)
		require.Nil(t, out)
	})

	t.Run("CommitmentScalarOp nil commitment", func(t *testing.T) {
		t.Parallel()
		out, err := key.CommitmentScalarOp(nil, scalar)
		require.Error(t, err)
		require.Nil(t, out)
	})

	t.Run("CommitmentScalarOp nil scalar", func(t *testing.T) {
		t.Parallel()
		out, err := key.CommitmentScalarOp(commitment, nil)
		require.Error(t, err)
		require.Nil(t, out)
	})

	t.Run("ReRandomise nil commitment", func(t *testing.T) {
		t.Parallel()
		out, err := key.ReRandomise(nil, witness)
		require.Error(t, err)
		require.Nil(t, out)
	})

	t.Run("ReRandomise nil witness shift", func(t *testing.T) {
		t.Parallel()
		out, err := key.ReRandomise(commitment, nil)
		require.Error(t, err)
		require.Nil(t, out)
	})

	t.Run("Shift nil commitment", func(t *testing.T) {
		t.Parallel()
		out, err := key.Shift(nil, message)
		require.Error(t, err)
		require.Nil(t, out)
	})

	t.Run("Shift nil message", func(t *testing.T) {
		t.Parallel()
		out, err := key.Shift(commitment, nil)
		require.Error(t, err)
		require.Nil(t, out)
	})

	t.Run("MessageScalarOp nil message", func(t *testing.T) {
		t.Parallel()
		out, err := key.MessageScalarOp(nil, scalar)
		require.Error(t, err)
		require.Nil(t, out)
	})

	t.Run("MessageScalarOp nil scalar", func(t *testing.T) {
		t.Parallel()
		out, err := key.MessageScalarOp(message, nil)
		require.Error(t, err)
		require.Nil(t, out)
	})
}
