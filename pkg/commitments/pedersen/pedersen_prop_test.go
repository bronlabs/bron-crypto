package pedersen_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	algebra_prop "github.com/bronlabs/bron-crypto/pkg/base/algebra/properties"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/commitments/testutils/properties"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func CommitmentKeyGenerator[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](tb testing.TB, group algebra.PrimeGroup[E, S]) *rapid.Generator[*pedersen.CommitmentKey[E, S]] {
	tb.Helper()
	return rapid.Custom(func(t *rapid.T) *pedersen.CommitmentKey[E, S] {
		gen := algebra_prop.NonOpIdentityDomainGenerator(tb, group)
		g := gen.Draw(t, "generator g")
		h := gen.Filter(func(e E) bool { return !e.Equal(g) }).Draw(t, "generator h")
		out, err := pedersen.NewCommitmentKeyUnchecked(g, h)
		require.NoError(t, err, "failed to create Pedersen commitment key")
		return out
	})
}

func TrapdoorKeyGenerator[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](tb testing.TB, group algebra.PrimeGroup[E, S]) *rapid.Generator[*pedersen.TrapdoorKey[E, S]] {
	tb.Helper()
	return rapid.Custom(func(t *rapid.T) *pedersen.TrapdoorKey[E, S] {
		gen := algebra_prop.NonOpIdentityDomainGenerator(tb, group)
		g := gen.Draw(t, "generator g")
		sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
		lambda, err := algebrautils.RandomNonIdentity(sf, pcg.NewRandomised())
		require.NoError(t, err, "failed to sample trapdoor value")
		out, err := pedersen.NewTrapdoorKey(g, lambda)
		require.NoError(t, err, "failed to create Pedersen trapdoor key")
		return out
	})
}

func CommitmentGenerator[K commitments.CommitmentKey[K, *pedersen.Message[S], *pedersen.Witness[S], *pedersen.Commitment[E, S]], E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](
	tb testing.TB, key commitments.CommitmentKey[K, *pedersen.Message[S], *pedersen.Witness[S], *pedersen.Commitment[E, S]],
) *rapid.Generator[*pedersen.Commitment[E, S]] {
	tb.Helper()
	var group algebra.PrimeGroup[E, S]
	switch k := any(key).(type) {
	case *pedersen.CommitmentKey[E, S]:
		group = k.CommitmentGroup()
	case *pedersen.TrapdoorKey[E, S]:
		group = k.CommitmentGroup()
	default:
		require.Fail(tb, "unexpected key type")
		return nil
	}
	return rapid.Map(algebra_prop.NonOpIdentityDomainGenerator(tb, group), func(c E) *pedersen.Commitment[E, S] {
		out, err := pedersen.NewCommitment(c)
		require.NoError(tb, err, "failed to create Pedersen commitment")
		return out
	})
}

func WitnessGenerator[K commitments.CommitmentKey[K, *pedersen.Message[S], *pedersen.Witness[S], *pedersen.Commitment[E, S]], E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](
	tb testing.TB, key commitments.CommitmentKey[K, *pedersen.Message[S], *pedersen.Witness[S], *pedersen.Commitment[E, S]],
) *rapid.Generator[*pedersen.Witness[S]] {
	tb.Helper()
	var sf algebra.PrimeField[S]
	switch k := any(key).(type) {
	case *pedersen.CommitmentKey[E, S]:
		sf = k.WitnessGroup()
	case *pedersen.TrapdoorKey[E, S]:
		sf = k.WitnessGroup()
	default:
		require.Fail(tb, "unexpected key type")
		return nil
	}
	return rapid.Map(algebra_prop.UniformDomainGenerator(tb, sf), func(w S) *pedersen.Witness[S] {
		out, err := pedersen.NewWitness(w)
		require.NoError(tb, err, "failed to create Pedersen witness")
		return out
	})
}

func MessageGenerator[K commitments.CommitmentKey[K, *pedersen.Message[S], *pedersen.Witness[S], *pedersen.Commitment[E, S]], E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](
	tb testing.TB, key commitments.CommitmentKey[K, *pedersen.Message[S], *pedersen.Witness[S], *pedersen.Commitment[E, S]],
) *rapid.Generator[*pedersen.Message[S]] {
	tb.Helper()
	var sf algebra.PrimeField[S]
	switch k := any(key).(type) {
	case *pedersen.CommitmentKey[E, S]:
		sf = k.MessageGroup()
	case *pedersen.TrapdoorKey[E, S]:
		sf = k.MessageGroup()
	default:
		require.Fail(tb, "unexpected key type")
		return nil
	}
	return rapid.Map(algebra_prop.UniformDomainGenerator(tb, sf), func(m S) *pedersen.Message[S] {
		out, err := pedersen.NewMessage(m)
		require.NoError(tb, err, "failed to create Pedersen message")
		return out
	})
}

func ScalarGenerator[K commitments.HomomorphicCommitmentKey[K, *pedersen.Message[S], *pedersen.Witness[S], *pedersen.Commitment[E, S], S], E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](
	tb testing.TB, key commitments.HomomorphicCommitmentKey[K, *pedersen.Message[S], *pedersen.Witness[S], *pedersen.Commitment[E, S], S],
) *rapid.Generator[S] {
	tb.Helper()
	var sf algebra.PrimeField[S]
	switch k := any(key).(type) {
	case *pedersen.CommitmentKey[E, S]:
		sf = k.WitnessGroup()
	case *pedersen.TrapdoorKey[E, S]:
		sf = k.WitnessGroup()
	default:
		require.Fail(tb, "unexpected key type")
		return nil
	}
	return algebra_prop.UniformDomainGenerator(tb, sf)
}

type GroupHomomorphicCommitmentKeyProperties[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] = properties.GroupHomomorphicCommitmentKeyProperties[
	*pedersen.CommitmentKey[E, S],
	*pedersen.Message[S], algebra.PrimeField[S], S,
	*pedersen.Witness[S], algebra.PrimeField[S], S,
	*pedersen.Commitment[E, S], algebra.PrimeGroup[E, S], E,
	S,
]

type GroupHomomorphicTrapdoorKeyProperties[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] = properties.GroupHomomorphicTrapdoorKeyProperties[
	*pedersen.CommitmentKey[E, S],
	*pedersen.TrapdoorKey[E, S],
	*pedersen.Message[S], algebra.PrimeField[S], S,
	*pedersen.Witness[S], algebra.PrimeField[S], S,
	*pedersen.Commitment[E, S], algebra.PrimeGroup[E, S], E,
	S,
]

func CommitmentKeyPropertySuite[
	E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S],
](tb testing.TB, group algebra.PrimeGroup[E, S]) *GroupHomomorphicCommitmentKeyProperties[E, S] {
	tb.Helper()
	return properties.NewGroupHomomorphicCommitmentKeyProperties(
		tb,
		prng.PRNGFuncTypeErase(pcg.NewRandomised),
		CommitmentKeyGenerator(tb, group),
		MessageGenerator,
		func(m1, m2 *pedersen.Message[S]) bool {
			return m1.Equal(m2)
		},
		func(w1, w2 *pedersen.Witness[S]) bool {
			return w1.Equal(w2)
		},
		ScalarGenerator,
		CommitmentGenerator,
		pedersen.NewMessage[S],
		pedersen.NewWitness[S],
		pedersen.NewCommitment[E, S],
		func(tb testing.TB, m *pedersen.Message[S], sc S) *pedersen.Message[S] {
			tb.Helper()
			expectedValue := m.Value().Mul(sc)
			out, err := pedersen.NewMessage(expectedValue)
			require.NoError(tb, err)
			return out
		},
		func(tb testing.TB, w *pedersen.Witness[S], sc S) *pedersen.Witness[S] {
			tb.Helper()
			expectedValue := w.Value().Mul(sc)
			out, err := pedersen.NewWitness(expectedValue)
			require.NoError(tb, err)
			return out
		},
		func(tb testing.TB, c *pedersen.Commitment[E, S], sc S) *pedersen.Commitment[E, S] {
			tb.Helper()
			expectedValue := c.Value().ScalarOp(sc)
			out, err := pedersen.NewCommitment(expectedValue)
			require.NoError(tb, err)
			return out
		},
	)
}

func TrapdoorKeyPropertySuite[
	E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S],
](tb testing.TB, group algebra.PrimeGroup[E, S]) *GroupHomomorphicTrapdoorKeyProperties[E, S] {
	tb.Helper()
	return properties.NewGroupHomomorphicTrapdoorKeyProperties(
		tb,
		prng.PRNGFuncTypeErase(pcg.NewRandomised),
		TrapdoorKeyGenerator(tb, group),
		MessageGenerator,
		func(m1, m2 *pedersen.Message[S]) bool {
			return m1.Equal(m2)
		},
		func(w1, w2 *pedersen.Witness[S]) bool {
			return w1.Equal(w2)
		},
		ScalarGenerator,
		CommitmentGenerator,
		pedersen.NewMessage[S],
		pedersen.NewWitness[S],
		pedersen.NewCommitment[E, S],
		func(tb testing.TB, m *pedersen.Message[S], sc S) *pedersen.Message[S] {
			tb.Helper()
			expectedValue := m.Value().Mul(sc)
			out, err := pedersen.NewMessage(expectedValue)
			require.NoError(tb, err)
			return out
		},
		func(tb testing.TB, w *pedersen.Witness[S], sc S) *pedersen.Witness[S] {
			tb.Helper()
			expectedValue := w.Value().Mul(sc)
			out, err := pedersen.NewWitness(expectedValue)
			require.NoError(tb, err)
			return out
		},
		func(tb testing.TB, c *pedersen.Commitment[E, S], sc S) *pedersen.Commitment[E, S] {
			tb.Helper()
			expectedValue := c.Value().ScalarOp(sc)
			out, err := pedersen.NewCommitment(expectedValue)
			require.NoError(tb, err)
			return out
		},
	)
}

func WitnessPropertySuite[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](tb testing.TB, group algebra.PrimeGroup[E, S]) *properties.WitnessProperties[*pedersen.Witness[S]] {
	tb.Helper()
	key, err := pedersen.SampleCommitmentKey(group, pcg.NewRandomised())
	require.NoError(tb, err, "failed to sample Pedersen commitment key")
	return &properties.WitnessProperties[*pedersen.Witness[S]]{
		WitnessGenerator: WitnessGenerator(tb, key),
		WitnessesAreEqual: func(w1, w2 *pedersen.Witness[S]) bool {
			return w1.Equal(w2)
		},
	}
}

func MessagePropertySuite[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](tb testing.TB, group algebra.PrimeGroup[E, S]) *properties.MessageProperties[*pedersen.Message[S]] {
	tb.Helper()
	key, err := pedersen.SampleCommitmentKey(group, pcg.NewRandomised())
	require.NoError(tb, err, "failed to sample Pedersen commitment key")
	return &properties.MessageProperties[*pedersen.Message[S]]{
		MessageGenerator: MessageGenerator(tb, key),
		MessagesAreEqual: func(m1, m2 *pedersen.Message[S]) bool {
			return m1.Equal(m2)
		},
	}
}

func CommitmentPropertySuite[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](tb testing.TB, group algebra.PrimeGroup[E, S]) *properties.CommitmentProperties[*pedersen.Commitment[E, S]] {
	tb.Helper()
	key, err := pedersen.SampleCommitmentKey(group, pcg.NewRandomised())
	require.NoError(tb, err, "failed to sample Pedersen commitment key")
	return &properties.CommitmentProperties[*pedersen.Commitment[E, S]]{
		CommitmentGenerator: CommitmentGenerator(tb, key),
		CommitmentsAreEqual: func(c1, c2 *pedersen.Commitment[E, S]) bool {
			return c1.Equal(c2)
		},
	}
}

func TestCommitmentKeyProperties(t *testing.T) {
	t.Parallel()
	t.Run("secp256k1", CommitmentKeyPropertySuite(t, k256.NewCurve()).CheckAll)
	t.Run("edwards25519", CommitmentKeyPropertySuite(t, edwards25519.NewPrimeSubGroup()).CheckAll)
}

func TestTrapdoorKeyProperties(t *testing.T) {
	t.Parallel()
	t.Run("secp256k1", TrapdoorKeyPropertySuite(t, k256.NewCurve()).CheckAll)
	t.Run("edwards25519", TrapdoorKeyPropertySuite(t, edwards25519.NewPrimeSubGroup()).CheckAll)
}

func TestWitnessProperties(t *testing.T) {
	t.Parallel()
	t.Run("secp256k1", WitnessPropertySuite(t, k256.NewCurve()).CheckAll)
	t.Run("edwards25519", WitnessPropertySuite(t, edwards25519.NewPrimeSubGroup()).CheckAll)
}

func TestMessageProperties(t *testing.T) {
	t.Parallel()
	t.Run("secp256k1", MessagePropertySuite(t, k256.NewCurve()).CheckAll)
	t.Run("edwards25519", MessagePropertySuite(t, edwards25519.NewPrimeSubGroup()).CheckAll)
}

func TestCommitmentProperties(t *testing.T) {
	t.Parallel()
	t.Run("secp256k1", CommitmentPropertySuite(t, k256.NewCurve()).CheckAll)
	t.Run("edwards25519", CommitmentPropertySuite(t, edwards25519.NewPrimeSubGroup()).CheckAll)
}
