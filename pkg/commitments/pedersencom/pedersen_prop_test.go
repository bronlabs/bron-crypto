package pedersencom_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	algebra_prop "github.com/bronlabs/bron-crypto/pkg/base/algebra/properties"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/prng"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/pedersencom"
	"github.com/bronlabs/bron-crypto/pkg/commitments/testutils/properties"
)

func CommitmentKeyGenerator[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](tb testing.TB, group algebra.PrimeGroup[E, S]) *rapid.Generator[*pedersencom.CommitmentKey[E, S]] {
	tb.Helper()
	return rapid.Custom(func(t *rapid.T) *pedersencom.CommitmentKey[E, S] {
		gen := algebra_prop.NonOpIdentityDomainGenerator(tb, group)
		g := gen.Draw(t, "generator g")
		h := gen.Filter(func(e E) bool { return !e.Equal(g) }).Draw(t, "generator h")
		out, err := pedersencom.NewCommitmentKeyUnchecked(g, h)
		require.NoError(t, err, "failed to create Pedersen commitment key")
		return out
	})
}

func TrapdoorKeyGenerator[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](tb testing.TB, group algebra.PrimeGroup[E, S]) *rapid.Generator[*pedersencom.TrapdoorKey[E, S]] {
	tb.Helper()
	return rapid.Custom(func(t *rapid.T) *pedersencom.TrapdoorKey[E, S] {
		gen := algebra_prop.NonOpIdentityDomainGenerator(tb, group)
		g := gen.Draw(t, "generator g")
		sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
		lambda, err := algebrautils.RandomNonIdentity(sf, pcg.NewRandomised())
		require.NoError(t, err, "failed to sample trapdoor value")
		out, err := pedersencom.NewTrapdoorKey(g, lambda)
		require.NoError(t, err, "failed to create Pedersen trapdoor key")
		return out
	})
}

func CommitmentGenerator[K commitments.CommitmentKey[K, *pedersencom.Message[S], *pedersencom.Witness[S], *pedersencom.Commitment[E, S]], E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](
	tb testing.TB, key commitments.CommitmentKey[K, *pedersencom.Message[S], *pedersencom.Witness[S], *pedersencom.Commitment[E, S]],
) *rapid.Generator[*pedersencom.Commitment[E, S]] {
	tb.Helper()
	var group algebra.PrimeGroup[E, S]
	switch k := any(key).(type) {
	case *pedersencom.CommitmentKey[E, S]:
		group = k.CommitmentGroup()
	case *pedersencom.TrapdoorKey[E, S]:
		group = k.CommitmentGroup()
	default:
		require.Fail(tb, "unexpected key type")
		return nil
	}
	return rapid.Map(algebra_prop.NonOpIdentityDomainGenerator(tb, group), func(c E) *pedersencom.Commitment[E, S] {
		out, err := pedersencom.NewCommitment(c)
		require.NoError(tb, err, "failed to create Pedersen commitment")
		return out
	})
}

func WitnessGenerator[K commitments.CommitmentKey[K, *pedersencom.Message[S], *pedersencom.Witness[S], *pedersencom.Commitment[E, S]], E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](
	tb testing.TB, key commitments.CommitmentKey[K, *pedersencom.Message[S], *pedersencom.Witness[S], *pedersencom.Commitment[E, S]],
) *rapid.Generator[*pedersencom.Witness[S]] {
	tb.Helper()
	var sf algebra.PrimeField[S]
	switch k := any(key).(type) {
	case *pedersencom.CommitmentKey[E, S]:
		sf = k.WitnessGroup()
	case *pedersencom.TrapdoorKey[E, S]:
		sf = k.WitnessGroup()
	default:
		require.Fail(tb, "unexpected key type")
		return nil
	}
	return rapid.Map(algebra_prop.UniformDomainGenerator(tb, sf), func(w S) *pedersencom.Witness[S] {
		out, err := pedersencom.NewWitness(w)
		require.NoError(tb, err, "failed to create Pedersen witness")
		return out
	})
}

func MessageGenerator[K commitments.CommitmentKey[K, *pedersencom.Message[S], *pedersencom.Witness[S], *pedersencom.Commitment[E, S]], E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](
	tb testing.TB, key commitments.CommitmentKey[K, *pedersencom.Message[S], *pedersencom.Witness[S], *pedersencom.Commitment[E, S]],
) *rapid.Generator[*pedersencom.Message[S]] {
	tb.Helper()
	var sf algebra.PrimeField[S]
	switch k := any(key).(type) {
	case *pedersencom.CommitmentKey[E, S]:
		sf = k.MessageGroup()
	case *pedersencom.TrapdoorKey[E, S]:
		sf = k.MessageGroup()
	default:
		require.Fail(tb, "unexpected key type")
		return nil
	}
	return rapid.Map(algebra_prop.UniformDomainGenerator(tb, sf), func(m S) *pedersencom.Message[S] {
		out, err := pedersencom.NewMessage(m)
		require.NoError(tb, err, "failed to create Pedersen message")
		return out
	})
}

func ScalarGenerator[K commitments.HomomorphicCommitmentKey[K, *pedersencom.Message[S], *pedersencom.Witness[S], *pedersencom.Commitment[E, S], S], E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](
	tb testing.TB, key commitments.HomomorphicCommitmentKey[K, *pedersencom.Message[S], *pedersencom.Witness[S], *pedersencom.Commitment[E, S], S],
) *rapid.Generator[S] {
	tb.Helper()
	var sf algebra.PrimeField[S]
	switch k := any(key).(type) {
	case *pedersencom.CommitmentKey[E, S]:
		sf = k.WitnessGroup()
	case *pedersencom.TrapdoorKey[E, S]:
		sf = k.WitnessGroup()
	default:
		require.Fail(tb, "unexpected key type")
		return nil
	}
	return algebra_prop.UniformDomainGenerator(tb, sf)
}

type GroupHomomorphicCommitmentKeyProperties[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] = properties.GroupHomomorphicCommitmentKeyProperties[
	*pedersencom.CommitmentKey[E, S],
	*pedersencom.Message[S], algebra.PrimeField[S], S,
	*pedersencom.Witness[S], algebra.PrimeField[S], S,
	*pedersencom.Commitment[E, S], algebra.PrimeGroup[E, S], E,
	S,
]

type GroupHomomorphicTrapdoorKeyProperties[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] = properties.GroupHomomorphicTrapdoorKeyProperties[
	*pedersencom.CommitmentKey[E, S],
	*pedersencom.TrapdoorKey[E, S],
	*pedersencom.Message[S], algebra.PrimeField[S], S,
	*pedersencom.Witness[S], algebra.PrimeField[S], S,
	*pedersencom.Commitment[E, S], algebra.PrimeGroup[E, S], E,
	S,
]

func CommitmentKeyPropertySuite[
	E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S],
](tb testing.TB, group algebra.PrimeGroup[E, S]) *GroupHomomorphicCommitmentKeyProperties[E, S] {
	tb.Helper()
	return properties.NewGroupHomomorphicCommitmentKeyProperties(
		tb,
		prng.FuncTypeErase(pcg.NewRandomised),
		CommitmentKeyGenerator(tb, group),
		MessageGenerator,
		func(m1, m2 *pedersencom.Message[S]) bool {
			return m1.Equal(m2)
		},
		func(w1, w2 *pedersencom.Witness[S]) bool {
			return w1.Equal(w2)
		},
		ScalarGenerator,
		func(tb testing.TB, n algebra.UnsignedNumeric) S {
			tb.Helper()
			sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
			out, err := sf.FromBytesBEReduce(n.BytesBE())
			require.NoError(tb, err, "failed to convert unsigned numeric to scalar: %v", n.BytesBE())
			return out
		},
		func(tb testing.TB, n algebra.SignedNumeric) S {
			tb.Helper()
			sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
			z, err := num.Z().FromSignedNumeric(n)
			require.NoError(tb, err, "failed to convert signed numeric to scalar: %v", n.AbsBytesBE())
			out, err := sf.FromBytesBEReduce(n.AbsBytesBE())
			require.NoError(tb, err, "failed to convert signed numeric to scalar: %v", n.AbsBytesBE())
			if z.IsNegative() {
				out = out.Neg()
			}
			return out
		},
		CommitmentGenerator,
		pedersencom.NewMessage[S],
		pedersencom.NewWitness[S],
		pedersencom.NewCommitment[E, S],
		func(tb testing.TB, m *pedersencom.Message[S], sc S) *pedersencom.Message[S] {
			tb.Helper()
			expectedValue := m.Value().Mul(sc)
			out, err := pedersencom.NewMessage(expectedValue)
			require.NoError(tb, err)
			return out
		},
		func(tb testing.TB, w *pedersencom.Witness[S], sc S) *pedersencom.Witness[S] {
			tb.Helper()
			expectedValue := w.Value().Mul(sc)
			out, err := pedersencom.NewWitness(expectedValue)
			require.NoError(tb, err)
			return out
		},
		func(tb testing.TB, c *pedersencom.Commitment[E, S], sc S) *pedersencom.Commitment[E, S] {
			tb.Helper()
			expectedValue := c.Value().ScalarOp(sc)
			out, err := pedersencom.NewCommitment(expectedValue)
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
		prng.FuncTypeErase(pcg.NewRandomised),
		TrapdoorKeyGenerator(tb, group),
		MessageGenerator,
		func(m1, m2 *pedersencom.Message[S]) bool {
			return m1.Equal(m2)
		},
		func(w1, w2 *pedersencom.Witness[S]) bool {
			return w1.Equal(w2)
		},
		ScalarGenerator,

		func(tb testing.TB, n algebra.UnsignedNumeric) S {
			tb.Helper()
			sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
			out, err := sf.FromBytesBEReduce(n.BytesBE())
			require.NoError(tb, err, "failed to convert unsigned numeric to scalar: %v", n.BytesBE())
			return out
		},
		func(tb testing.TB, n algebra.SignedNumeric) S {
			tb.Helper()
			sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
			z, err := num.Z().FromSignedNumeric(n)
			require.NoError(tb, err, "failed to convert signed numeric to scalar: %v", n.AbsBytesBE())
			out, err := sf.FromBytesBEReduce(n.AbsBytesBE())
			require.NoError(tb, err, "failed to convert signed numeric to scalar: %v", n.AbsBytesBE())
			if z.IsNegative() {
				out = out.Neg()
			}
			return out
		},
		CommitmentGenerator,
		pedersencom.NewMessage[S],
		pedersencom.NewWitness[S],
		pedersencom.NewCommitment[E, S],
		func(tb testing.TB, m *pedersencom.Message[S], sc S) *pedersencom.Message[S] {
			tb.Helper()
			expectedValue := m.Value().Mul(sc)
			out, err := pedersencom.NewMessage(expectedValue)
			require.NoError(tb, err)
			return out
		},
		func(tb testing.TB, w *pedersencom.Witness[S], sc S) *pedersencom.Witness[S] {
			tb.Helper()
			expectedValue := w.Value().Mul(sc)
			out, err := pedersencom.NewWitness(expectedValue)
			require.NoError(tb, err)
			return out
		},
		func(tb testing.TB, c *pedersencom.Commitment[E, S], sc S) *pedersencom.Commitment[E, S] {
			tb.Helper()
			expectedValue := c.Value().ScalarOp(sc)
			out, err := pedersencom.NewCommitment(expectedValue)
			require.NoError(tb, err)
			return out
		},
	)
}

func WitnessPropertySuite[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](tb testing.TB, group algebra.PrimeGroup[E, S]) *properties.WitnessProperties[*pedersencom.Witness[S]] {
	tb.Helper()
	key, err := pedersencom.SampleCommitmentKey(group, pcg.NewRandomised())
	require.NoError(tb, err, "failed to sample Pedersen commitment key")
	return &properties.WitnessProperties[*pedersencom.Witness[S]]{
		WitnessGenerator: WitnessGenerator(tb, key),
		WitnessesAreEqual: func(w1, w2 *pedersencom.Witness[S]) bool {
			return w1.Equal(w2)
		},
	}
}

func MessagePropertySuite[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](tb testing.TB, group algebra.PrimeGroup[E, S]) *properties.MessageProperties[*pedersencom.Message[S]] {
	tb.Helper()
	key, err := pedersencom.SampleCommitmentKey(group, pcg.NewRandomised())
	require.NoError(tb, err, "failed to sample Pedersen commitment key")
	return &properties.MessageProperties[*pedersencom.Message[S]]{
		MessageGenerator: MessageGenerator(tb, key),
		MessagesAreEqual: func(m1, m2 *pedersencom.Message[S]) bool {
			return m1.Equal(m2)
		},
	}
}

func CommitmentPropertySuite[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](tb testing.TB, group algebra.PrimeGroup[E, S]) *properties.CommitmentProperties[*pedersencom.Commitment[E, S]] {
	tb.Helper()
	key, err := pedersencom.SampleCommitmentKey(group, pcg.NewRandomised())
	require.NoError(tb, err, "failed to sample Pedersen commitment key")
	return &properties.CommitmentProperties[*pedersencom.Commitment[E, S]]{
		CommitmentGenerator: CommitmentGenerator(tb, key),
		CommitmentsAreEqual: func(c1, c2 *pedersencom.Commitment[E, S]) bool {
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
