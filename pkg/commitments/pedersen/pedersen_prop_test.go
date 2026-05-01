package pedersen_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	algebra_prop "github.com/bronlabs/bron-crypto/pkg/base/algebra/properties"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
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
	return rapid.Custom(func(t *rapid.T) *pedersen.TrapdoorKey[E, S] {
		sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
		g := algebra_prop.NonOpIdentityDomainGenerator(tb, group).Draw(t, "generator g")
		lambda := ScalarGenerator(tb, sf).Draw(t, "lambda")
		out, err := pedersen.NewTrapdoorKey(g, lambda)
		require.NoError(t, err, "failed to create Pedersen trapdoor key")
		return out
	})
}

func CommitmentGenerator[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](tb testing.TB, group algebra.PrimeGroup[E, S]) *rapid.Generator[*pedersen.Commitment[E, S]] {
	tb.Helper()
	return rapid.Map(algebra_prop.NonOpIdentityDomainGenerator(tb, group), func(c E) *pedersen.Commitment[E, S] {
		out, err := pedersen.NewCommitment(c)
		require.NoError(tb, err, "failed to create Pedersen commitment")
		return out
	})
}

func WitnessGenerator[S algebra.PrimeFieldElement[S]](tb testing.TB, field algebra.PrimeField[S]) *rapid.Generator[*pedersen.Witness[S]] {
	tb.Helper()
	return rapid.Map(algebra_prop.UniformDomainGenerator(tb, field), func(w S) *pedersen.Witness[S] {
		out, err := pedersen.NewWitness(w)
		require.NoError(tb, err, "failed to create Pedersen witness")
		return out
	})
}

func MessageGenerator[S algebra.PrimeFieldElement[S]](tb testing.TB, field algebra.PrimeField[S]) *rapid.Generator[*pedersen.Message[S]] {
	tb.Helper()
	return rapid.Map(algebra_prop.UniformDomainGenerator(tb, field), func(m S) *pedersen.Message[S] {
		out, err := pedersen.NewMessage(m)
		require.NoError(tb, err, "failed to create Pedersen message")
		return out
	})
}

func ScalarGenerator[S algebra.PrimeFieldElement[S]](tb testing.TB, field algebra.PrimeField[S]) *rapid.Generator[S] {
	tb.Helper()
	return algebra_prop.UniformDomainGenerator(tb, field)
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
	sf, err := algebra.StructureAs[algebra.PrimeField[S]](group.ScalarStructure())
	require.NoError(tb, err, "group scalar structure must be a prime field")
	return properties.NewGroupHomomorphicCommitmentKeyProperties(
		tb,
		prng.PRNGFuncTypeErase(pcg.NewRandomised),
		CommitmentKeyGenerator(tb, group),
		MessageGenerator(tb, sf),
		func(m1, m2 *pedersen.Message[S]) bool {
			return m1.Equal(m2)
		},
		func(w1, w2 *pedersen.Witness[S]) bool {
			return w1.Equal(w2)
		},
		ScalarGenerator(tb, sf),
		CommitmentGenerator(tb, group),
		pedersen.NewMessage[S],
		pedersen.NewWitness[S],
		pedersen.NewCommitment[E, S],
	)
}

func TrapdoorKeyPropertySuite[
	E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S],
](tb testing.TB, group algebra.PrimeGroup[E, S]) *GroupHomomorphicTrapdoorKeyProperties[E, S] {
	tb.Helper()
	sf, err := algebra.StructureAs[algebra.PrimeField[S]](group.ScalarStructure())
	require.NoError(tb, err, "group scalar structure must be a prime field")
	return properties.NewGroupHomomorphicTrapdoorKeyProperties(
		tb,
		prng.PRNGFuncTypeErase(pcg.NewRandomised),
		TrapdoorKeyGenerator(tb, group),
		MessageGenerator(tb, sf),
		func(m1, m2 *pedersen.Message[S]) bool {
			return m1.Equal(m2)
		},
		func(w1, w2 *pedersen.Witness[S]) bool {
			return w1.Equal(w2)
		},
		ScalarGenerator(tb, sf),
		CommitmentGenerator(tb, group),
		pedersen.NewMessage[S],
		pedersen.NewWitness[S],
		pedersen.NewCommitment[E, S],
		CommitmentKeyGenerator(tb, group),
	)
}

func WitnessPropertySuite[S algebra.PrimeFieldElement[S]](tb testing.TB, field algebra.PrimeField[S]) *properties.WitnessProperties[*pedersen.Witness[S]] {
	tb.Helper()
	return &properties.WitnessProperties[*pedersen.Witness[S]]{
		WitnessGenerator: WitnessGenerator(tb, field),
		WitnessesAreEqual: func(w1, w2 *pedersen.Witness[S]) bool {
			return w1.Equal(w2)
		},
	}
}

func MessagePropertySuite[S algebra.PrimeFieldElement[S]](tb testing.TB, field algebra.PrimeField[S]) *properties.MessageProperties[*pedersen.Message[S]] {
	tb.Helper()
	return &properties.MessageProperties[*pedersen.Message[S]]{
		MessageGenerator: MessageGenerator(tb, field),
		MessagesAreEqual: func(m1, m2 *pedersen.Message[S]) bool {
			return m1.Equal(m2)
		},
	}
}

func CommitmentPropertySuite[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](tb testing.TB, group algebra.PrimeGroup[E, S]) *properties.CommitmentProperties[*pedersen.Commitment[E, S]] {
	tb.Helper()
	return &properties.CommitmentProperties[*pedersen.Commitment[E, S]]{
		CommitmentGenerator: CommitmentGenerator(tb, group),
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
	t.Run("secp256k1", WitnessPropertySuite(t, k256.NewScalarField()).CheckAll)
	t.Run("edwards25519", WitnessPropertySuite(t, edwards25519.NewScalarField()).CheckAll)
}

func TestMessageProperties(t *testing.T) {
	t.Parallel()
	t.Run("secp256k1", MessagePropertySuite(t, k256.NewScalarField()).CheckAll)
	t.Run("edwards25519", MessagePropertySuite(t, edwards25519.NewScalarField()).CheckAll)
}

func TestCommitmentProperties(t *testing.T) {
	t.Parallel()
	t.Run("secp256k1", CommitmentPropertySuite(t, k256.NewCurve()).CheckAll)
	t.Run("edwards25519", CommitmentPropertySuite(t, edwards25519.NewPrimeSubGroup()).CheckAll)
}

func TestScalarMulWorks(t *testing.T) {
	t.Parallel()
	group := k256.NewCurve()
	sf := k256.NewScalarField()

	t.Run("WitnessScalarMul", rapid.MakeCheck(func(rt *rapid.T) {
		key := CommitmentKeyGenerator(t, group).Draw(rt, "commitment key")
		w := WitnessGenerator(t, key.WitnessGroup()).Draw(rt, "witness")
		sc := ScalarGenerator(t, key.WitnessGroup()).Draw(rt, "scalar")

		actual, err := key.WitnessScalarOp(w, sc)
		require.NoError(t, err, "failed to compute witness scalar multiplication")

		expected, err := pedersen.NewWitness(w.Value().Mul(sc))
		require.NoError(t, err, "failed to compute expected witness scalar multiplication")

		require.True(t, expected.Equal(actual), "witness scalar multiplication result is incorrect")
	}))

	t.Run("MessageScalarMul", rapid.MakeCheck(func(rt *rapid.T) {
		key := CommitmentKeyGenerator(t, group).Draw(rt, "commitment key")
		m := MessageGenerator(t, key.MessageGroup()).Draw(rt, "message")
		sc := ScalarGenerator(t, key.MessageGroup()).Draw(rt, "scalar")

		actual, err := key.MessageScalarOp(m, sc)
		require.NoError(t, err, "failed to compute message scalar multiplication")

		expected, err := pedersen.NewMessage(m.Value().Mul(sc))
		require.NoError(t, err, "failed to compute expected message scalar multiplication")

		require.True(t, expected.Equal(actual), "message scalar multiplication result is incorrect")
	}))

	t.Run("CommitmentScalarMul", rapid.MakeCheck(func(rt *rapid.T) {
		key := CommitmentKeyGenerator(t, group).Draw(rt, "commitment key")
		c := CommitmentGenerator(t, group).Draw(rt, "commitment")
		sc := ScalarGenerator(t, sf).Draw(rt, "scalar")

		actual, err := key.CommitmentScalarOp(c, sc)
		require.NoError(t, err, "failed to compute commitment scalar multiplication")

		expected, err := pedersen.NewCommitment(c.Value().ScalarMul(sc))
		require.NoError(t, err, "failed to compute expected commitment scalar multiplication")

		require.True(t, expected.Equal(actual), "commitment scalar multiplication result is incorrect")
	}))
}
