package intcom_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

const testKeyLen = 64

type badReader struct{}

func (badReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestNewCommitment(t *testing.T) {
	t.Parallel()

	t.Run("nil value rejected", func(t *testing.T) {
		t.Parallel()
		c, err := intcom.NewCommitment(nil)
		require.Error(t, err)
		require.Nil(t, c)
	})

	t.Run("valid value succeeds", func(t *testing.T) {
		t.Parallel()
		group, err := znstar.SampleSafeRSAGroup(testKeyLen, pcg.NewRandomised())
		require.NoError(t, err)
		v, err := group.RandomQuadraticResidue(pcg.NewRandomised())
		require.NoError(t, err)
		c, err := intcom.NewCommitment(v.ForgetOrder())
		require.NoError(t, err)
		require.NotNil(t, c)
		require.True(t, c.Value().Equal(v.ForgetOrder()))
	})
}

func TestNewWitness(t *testing.T) {
	t.Parallel()

	t.Run("nil value rejected", func(t *testing.T) {
		t.Parallel()
		w, err := intcom.NewWitness(nil)
		require.Error(t, err)
		require.Nil(t, w)
	})

	t.Run("valid value succeeds", func(t *testing.T) {
		t.Parallel()
		v := num.Z().FromInt64(42)
		w, err := intcom.NewWitness(v)
		require.NoError(t, err)
		require.NotNil(t, w)
		require.True(t, w.Value().Equal(v))
	})
}

func TestNewMessage(t *testing.T) {
	t.Parallel()

	t.Run("nil value rejected", func(t *testing.T) {
		t.Parallel()
		m, err := intcom.NewMessage(nil)
		require.Error(t, err)
		require.Nil(t, m)
	})

	t.Run("valid value succeeds", func(t *testing.T) {
		t.Parallel()
		v := num.Z().FromInt64(7)
		m, err := intcom.NewMessage(v)
		require.NoError(t, err)
		require.NotNil(t, m)
		require.True(t, m.Value().Equal(v))
	})
}

func TestSamplePedersenParameters(t *testing.T) {
	t.Parallel()

	t.Run("nil prng rejected", func(t *testing.T) {
		t.Parallel()
		group, s, tt, lambda, err := intcom.SamplePedersenParameters(testKeyLen, nil)
		require.Error(t, err)
		require.Nil(t, group)
		require.Nil(t, s)
		require.Nil(t, tt)
		require.Nil(t, lambda)
	})

	t.Run("failing reader propagates error", func(t *testing.T) {
		t.Parallel()
		group, s, tt, lambda, err := intcom.SamplePedersenParameters(testKeyLen, badReader{})
		require.Error(t, err)
		require.Nil(t, group)
		require.Nil(t, s)
		require.Nil(t, tt)
		require.Nil(t, lambda)
	})

	t.Run("valid output: t generates QR and s = t^lambda", func(t *testing.T) {
		t.Parallel()
		group, s, tt, lambda, err := intcom.SamplePedersenParameters(testKeyLen, pcg.NewRandomised())
		require.NoError(t, err)
		require.NotNil(t, group)
		require.NotNil(t, s)
		require.NotNil(t, tt)
		require.NotNil(t, lambda)

		require.True(t, tt.Value().Decrement().Nat().Coprime(group.Modulus().Nat()),
			"t must be a generator of QR(NHat): gcd(t-1, NHat) = 1")

		tKnown, err := tt.LearnOrder(group)
		require.NoError(t, err)
		sExpected := tKnown.ExpI(lambda.Lift()).ForgetOrder()
		require.True(t, s.Equal(sExpected),
			"trapdoor invariant: s must equal t^lambda")

		require.True(t, lambda.IsUnit(),
			"lambda must be a unit mod φ(NHat)/4 so the trapdoor is invertible")
	})

	t.Run("successive samples produce distinct lambdas", func(t *testing.T) {
		t.Parallel()
		prng := pcg.NewRandomised()
		_, _, _, l1, err := intcom.SamplePedersenParameters(testKeyLen, prng)
		require.NoError(t, err)
		_, _, _, l2, err := intcom.SamplePedersenParameters(testKeyLen, prng)
		require.NoError(t, err)
		require.False(t, l1.Equal(l2))
	})
}

func TestSampleCommitmentKey(t *testing.T) {
	t.Parallel()

	t.Run("nil prng rejected", func(t *testing.T) {
		t.Parallel()
		k, err := intcom.SampleCommitmentKey(testKeyLen, nil)
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("failing reader propagates error", func(t *testing.T) {
		t.Parallel()
		k, err := intcom.SampleCommitmentKey(testKeyLen, badReader{})
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("valid output: s and t are distinct, non-identity, torsion-free", func(t *testing.T) {
		t.Parallel()
		k, err := intcom.SampleCommitmentKey(testKeyLen, pcg.NewRandomised())
		require.NoError(t, err)
		require.NotNil(t, k)
		require.False(t, k.S().Equal(k.T()))
		require.False(t, k.S().IsOne())
		require.False(t, k.T().IsOne())
		require.True(t, k.S().IsTorsionFree())
		require.True(t, k.T().IsTorsionFree())
	})

	t.Run("successive samples produce distinct keys", func(t *testing.T) {
		t.Parallel()
		prng := pcg.NewRandomised()
		k1, err := intcom.SampleCommitmentKey(testKeyLen, prng)
		require.NoError(t, err)
		k2, err := intcom.SampleCommitmentKey(testKeyLen, prng)
		require.NoError(t, err)
		require.False(t, k1.Equal(k2))
	})
}

func TestSampleTrapdoorKey(t *testing.T) {
	t.Parallel()

	t.Run("nil prng rejected", func(t *testing.T) {
		t.Parallel()
		tk, err := intcom.SampleTrapdoorKey(testKeyLen, nil)
		require.Error(t, err)
		require.Nil(t, tk)
	})

	t.Run("failing reader propagates error", func(t *testing.T) {
		t.Parallel()
		tk, err := intcom.SampleTrapdoorKey(testKeyLen, badReader{})
		require.Error(t, err)
		require.Nil(t, tk)
	})

	t.Run("valid output: s = t^lambda invariant holds", func(t *testing.T) {
		t.Parallel()
		tk, err := intcom.SampleTrapdoorKey(testKeyLen, pcg.NewRandomised())
		require.NoError(t, err)
		require.NotNil(t, tk)

		tKnown, err := tk.T().LearnOrder(tk.Group())
		require.NoError(t, err)
		sExpected := tKnown.ExpI(tk.Lambda().Lift()).ForgetOrder()
		require.True(t, tk.S().Equal(sExpected),
			"trapdoor key invariant: s must equal t^lambda")

		require.True(t, tk.Lambda().IsUnit())
		require.False(t, tk.Lambda().IsOne())
	})

	t.Run("successive samples produce distinct trapdoors", func(t *testing.T) {
		t.Parallel()
		prng := pcg.NewRandomised()
		tk1, err := intcom.SampleTrapdoorKey(testKeyLen, prng)
		require.NoError(t, err)
		tk2, err := intcom.SampleTrapdoorKey(testKeyLen, prng)
		require.NoError(t, err)
		require.False(t, tk1.Lambda().Equal(tk2.Lambda()))
	})
}

func TestExtractCommitmentKey(t *testing.T) {
	t.Parallel()

	group, err := znstar.SampleSafeRSAGroup(testKeyLen, pcg.NewRandomised())
	require.NoError(t, err)

	t.Run("nil transcript rejected", func(t *testing.T) {
		t.Parallel()
		k, err := intcom.ExtractCommitmentKey(nil, "label", group)
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("empty label rejected", func(t *testing.T) {
		t.Parallel()
		k, err := intcom.ExtractCommitmentKey(hagrid.NewTranscript("test"), "", group)
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("nil group rejected", func(t *testing.T) {
		t.Parallel()
		k, err := intcom.ExtractCommitmentKey[*modular.OddPrimeFactors](hagrid.NewTranscript("test"), "label", nil) //nolint:infertypeargs // nil arg blocks inference
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("valid extraction succeeds", func(t *testing.T) {
		t.Parallel()
		k, err := intcom.ExtractCommitmentKey(hagrid.NewTranscript("test"), "label", group)
		require.NoError(t, err)
		require.NotNil(t, k)
		require.False(t, k.S().Equal(k.T()))
		require.False(t, k.S().IsOne())
		require.False(t, k.T().IsOne())
	})

	t.Run("deterministic on equal transcripts and labels", func(t *testing.T) {
		t.Parallel()
		t1 := hagrid.NewTranscript("test")
		t2 := hagrid.NewTranscript("test")
		t1.AppendBytes("ctx", []byte("payload"))
		t2.AppendBytes("ctx", []byte("payload"))

		k1, err := intcom.ExtractCommitmentKey(t1, "label", group)
		require.NoError(t, err)
		k2, err := intcom.ExtractCommitmentKey(t2, "label", group)
		require.NoError(t, err)
		require.True(t, k1.Equal(k2))
	})

	t.Run("different labels yield different keys", func(t *testing.T) {
		t.Parallel()
		k1, err := intcom.ExtractCommitmentKey(hagrid.NewTranscript("test"), "label-a", group)
		require.NoError(t, err)
		k2, err := intcom.ExtractCommitmentKey(hagrid.NewTranscript("test"), "label-b", group)
		require.NoError(t, err)
		require.False(t, k1.Equal(k2))
	})

	t.Run("different transcript states yield different keys", func(t *testing.T) {
		t.Parallel()
		t1 := hagrid.NewTranscript("test")
		t2 := hagrid.NewTranscript("test")
		t1.AppendBytes("ctx", []byte("payload-a"))
		t2.AppendBytes("ctx", []byte("payload-b"))

		k1, err := intcom.ExtractCommitmentKey(t1, "label", group)
		require.NoError(t, err)
		k2, err := intcom.ExtractCommitmentKey(t2, "label", group)
		require.NoError(t, err)
		require.False(t, k1.Equal(k2))
	})
}

func TestNewTrapdoorKey(t *testing.T) {
	t.Parallel()

	group, _, tValue, lambda, err := intcom.SamplePedersenParameters(testKeyLen, pcg.NewRandomised())
	require.NoError(t, err)

	tKnown, err := tValue.LearnOrder(group)
	require.NoError(t, err)

	t.Run("nil t rejected", func(t *testing.T) {
		t.Parallel()
		tk, err := intcom.NewTrapdoorKey(nil, lambda)
		require.Error(t, err)
		require.Nil(t, tk)
	})

	t.Run("nil lambda rejected", func(t *testing.T) {
		t.Parallel()
		tk, err := intcom.NewTrapdoorKey(tKnown, nil)
		require.Error(t, err)
		require.Nil(t, tk)
	})

	t.Run("identity t rejected", func(t *testing.T) {
		t.Parallel()
		tk, err := intcom.NewTrapdoorKey(group.OpIdentity(), lambda)
		require.Error(t, err)
		require.Nil(t, tk)
	})

	t.Run("lambda with mismatched modulus rejected", func(t *testing.T) {
		t.Parallel()
		otherModulus, err := num.NPlus().FromUint64(7)
		require.NoError(t, err)
		otherZMod, err := num.NewZMod(otherModulus)
		require.NoError(t, err)
		badLambda := otherZMod.FromUint64(3)
		tk, err := intcom.NewTrapdoorKey(tKnown, badLambda)
		require.Error(t, err)
		require.Nil(t, tk)
	})

	t.Run("lambda equal to one rejected", func(t *testing.T) {
		t.Parallel()
		zMod, err := num.NewZMod(lambda.Modulus())
		require.NoError(t, err)
		tk, err := intcom.NewTrapdoorKey(tKnown, zMod.One())
		require.Error(t, err)
		require.Nil(t, tk)
	})

	t.Run("valid input: s = t^lambda invariant holds", func(t *testing.T) {
		t.Parallel()
		tk, err := intcom.NewTrapdoorKey(tKnown, lambda)
		require.NoError(t, err)
		require.NotNil(t, tk)
		require.True(t, tk.Lambda().Equal(lambda))
		require.True(t, tk.T().Equal(tKnown.ForgetOrder()))

		sExpected := tKnown.ExpI(lambda.Lift()).ForgetOrder()
		require.True(t, tk.S().Equal(sExpected),
			"trapdoor key invariant: s must equal t^lambda")
	})
}
