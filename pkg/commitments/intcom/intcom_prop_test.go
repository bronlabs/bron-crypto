package intcom_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/prng"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/commitments/testutils/properties"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func CommitmentKeyGenerator(tb testing.TB, keyLen int) *rapid.Generator[*intcom.CommitmentKey] {
	tb.Helper()
	return rapid.Custom(func(rt *rapid.T) *intcom.CommitmentKey {
		seed := rapid.Uint64().Draw(rt, "pcg seed")
		salt := rapid.Uint64().Draw(rt, "pcg salt")
		prng := pcg.New(seed, salt)
		key, err := intcom.SampleCommitmentKey(uint(keyLen), prng)
		require.NoError(rt, err, "failed to sample commitment key")
		return key
	})
}

func TrapdoorKeyGenerator(tb testing.TB, keyLen int) *rapid.Generator[*intcom.TrapdoorKey] {
	tb.Helper()
	return rapid.Custom(func(rt *rapid.T) *intcom.TrapdoorKey {
		seed := rapid.Uint64().Draw(rt, "pcg seed")
		salt := rapid.Uint64().Draw(rt, "pcg salt")
		prng := pcg.New(seed, salt)
		key, err := intcom.SampleTrapdoorKey(uint(keyLen), prng)
		require.NoError(rt, err, "failed to sample trapdoor key")
		return key
	})
}

func CommitmentGenerator[K commitments.CommitmentKey[K, *intcom.Message, *intcom.Witness, *intcom.Commitment]](tb testing.TB, key commitments.CommitmentKey[K, *intcom.Message, *intcom.Witness, *intcom.Commitment]) *rapid.Generator[*intcom.Commitment] {
	tb.Helper()
	obj, ok := key.(interface {
		CommitmentGroup() *znstar.RSAGroupUnknownOrder
	})
	require.True(tb, ok, "commitment key does not implement CommitmentGroup")
	return rapid.Custom(func(rt *rapid.T) *intcom.Commitment {
		seed := rapid.Uint64().Draw(rt, "pcg seed")
		salt := rapid.Uint64().Draw(rt, "pcg salt")
		prng := pcg.New(seed, salt)
		c, err := obj.CommitmentGroup().RandomQuadraticResidue(prng)
		require.NoError(rt, err, "failed to sample commitment")
		out, err := intcom.NewCommitment(c.ForgetOrder())
		require.NoError(rt, err, "failed to create commitment")
		return out
	})
}

func WitnessGenerator[K commitments.CommitmentKey[K, *intcom.Message, *intcom.Witness, *intcom.Commitment]](tb testing.TB, key commitments.CommitmentKey[K, *intcom.Message, *intcom.Witness, *intcom.Commitment]) *rapid.Generator[*intcom.Witness] {
	tb.Helper()
	return rapid.Custom(func(rt *rapid.T) *intcom.Witness {
		seed := rapid.Uint64().Draw(rt, "pcg seed")
		salt := rapid.Uint64().Draw(rt, "pcg salt")
		prng := pcg.New(seed, salt)
		w, err := key.SampleWitness(prng)
		require.NoError(rt, err, "failed to sample witness")
		return w
	})
}

func MessageGenerator[K commitments.CommitmentKey[K, *intcom.Message, *intcom.Witness, *intcom.Commitment]](tb testing.TB, key commitments.CommitmentKey[K, *intcom.Message, *intcom.Witness, *intcom.Commitment]) *rapid.Generator[*intcom.Message] {
	tb.Helper()
	obj, ok := key.(interface {
		CommitmentGroup() *znstar.RSAGroupUnknownOrder
	})
	require.True(tb, ok, "commitment key does not implement Group")
	return rapid.Custom(func(rt *rapid.T) *intcom.Message {
		seed := rapid.Uint64().Draw(rt, "pcg seed")
		salt := rapid.Uint64().Draw(rt, "pcg salt")
		prng := pcg.New(seed, salt)
		modulus := obj.CommitmentGroup().Modulus()
		m, err := num.Z().Random(modulus.Lift().Neg(), modulus.Lift(), prng)
		require.NoError(rt, err)
		out, err := intcom.NewMessage(m)
		require.NoError(rt, err, "failed to create message")
		return out
	})
}

func ScalarGenerator[K commitments.HomomorphicCommitmentKey[K, *intcom.Message, *intcom.Witness, *intcom.Commitment, *num.Int]](tb testing.TB, key commitments.HomomorphicCommitmentKey[K, *intcom.Message, *intcom.Witness, *intcom.Commitment, *num.Int]) *rapid.Generator[*num.Int] {
	tb.Helper()
	obj, ok := key.(interface {
		CommitmentGroup() *znstar.RSAGroupUnknownOrder
	})
	require.True(tb, ok, "commitment key does not implement Group")
	return rapid.Custom(func(rt *rapid.T) *num.Int {
		seed := rapid.Uint64().Draw(rt, "pcg seed")
		salt := rapid.Uint64().Draw(rt, "pcg salt")
		prng := pcg.New(seed, salt)
		modulus := obj.CommitmentGroup().Modulus()
		s, err := num.Z().Random(modulus.Lift().Neg(), modulus.Lift(), prng)
		require.NoError(rt, err)
		return s
	})
}

type GroupHomomorphicCommitmentKeyProperties = properties.GroupHomomorphicCommitmentKeyProperties[
	*intcom.CommitmentKey,
	*intcom.Message, *num.Integers, *num.Int,
	*intcom.Witness, *num.Integers, *num.Int,
	*intcom.Commitment, *znstar.RSAGroupUnknownOrder, *znstar.RSAGroupElementUnknownOrder,
	*num.Int,
]

type GroupHomomorphicTrapdoorKeyProperties = properties.GroupHomomorphicTrapdoorKeyProperties[
	*intcom.CommitmentKey,
	*intcom.TrapdoorKey,
	*intcom.Message, *num.Integers, *num.Int,
	*intcom.Witness, *num.Integers, *num.Int,
	*intcom.Commitment, *znstar.RSAGroupUnknownOrder, *znstar.RSAGroupElementUnknownOrder,
	*num.Int,
]

func CommitmentKeyPropertySuite(tb testing.TB, keyLen int) *GroupHomomorphicCommitmentKeyProperties {
	tb.Helper()
	return properties.NewGroupHomomorphicCommitmentKeyProperties(
		tb,
		prng.PRNGFuncTypeErase(pcg.NewRandomised),
		CommitmentKeyGenerator(tb, keyLen),
		MessageGenerator,
		func(m1, m2 *intcom.Message) bool { return m1.Equal(m2) },
		func(w1, w2 *intcom.Witness) bool { return w1.Equal(w2) },
		ScalarGenerator,
		CommitmentGenerator,
		intcom.NewMessage,
		intcom.NewWitness,
		intcom.NewCommitment,
		func(tb testing.TB, message *intcom.Message, scalar *num.Int) *intcom.Message {
			tb.Helper()
			out, err := intcom.NewMessage(message.Value().Mul(scalar))
			require.NoError(tb, err)
			return out
		},
		func(tb testing.TB, witness *intcom.Witness, scalar *num.Int) *intcom.Witness {
			tb.Helper()
			out, err := intcom.NewWitness(witness.Value().Mul(scalar))
			require.NoError(tb, err)
			return out
		},
		func(tb testing.TB, commitment *intcom.Commitment, scalar *num.Int) *intcom.Commitment {
			tb.Helper()
			out, err := intcom.NewCommitment(commitment.Value().ScalarOp(scalar))
			require.NoError(tb, err)
			return out
		},
	)
}

func TrapdoorKeyPropertySuite(tb testing.TB, keyLen int) *GroupHomomorphicTrapdoorKeyProperties {
	tb.Helper()
	return properties.NewGroupHomomorphicTrapdoorKeyProperties(
		tb,
		prng.PRNGFuncTypeErase(pcg.NewRandomised),
		TrapdoorKeyGenerator(tb, keyLen),
		MessageGenerator,
		func(m1, m2 *intcom.Message) bool { return m1.Equal(m2) },
		func(w1, w2 *intcom.Witness) bool { return w1.Equal(w2) },
		ScalarGenerator,
		CommitmentGenerator,
		intcom.NewMessage,
		intcom.NewWitness,
		intcom.NewCommitment,
		func(tb testing.TB, message *intcom.Message, scalar *num.Int) *intcom.Message {
			tb.Helper()
			out, err := intcom.NewMessage(message.Value().Mul(scalar))
			require.NoError(tb, err)
			return out
		},
		func(tb testing.TB, witness *intcom.Witness, scalar *num.Int) *intcom.Witness {
			tb.Helper()
			out, err := intcom.NewWitness(witness.Value().Mul(scalar))
			require.NoError(tb, err)
			return out
		},
		func(tb testing.TB, commitment *intcom.Commitment, scalar *num.Int) *intcom.Commitment {
			tb.Helper()
			out, err := intcom.NewCommitment(commitment.Value().ScalarOp(scalar))
			require.NoError(tb, err)
			return out
		},
	)
}

func WitnessPropertySuite(tb testing.TB, keyLen int) *properties.WitnessProperties[*intcom.Witness] {
	tb.Helper()
	key, err := intcom.SampleCommitmentKey(uint(keyLen), pcg.NewRandomised())
	require.NoError(tb, err, "failed to sample commitment key")
	return &properties.WitnessProperties[*intcom.Witness]{
		WitnessGenerator: WitnessGenerator(tb, key),
		WitnessesAreEqual: func(w1, w2 *intcom.Witness) bool {
			return w1.Equal(w2)
		},
	}
}

func MessagePropertySuite(tb testing.TB, keyLen int) *properties.MessageProperties[*intcom.Message] {
	tb.Helper()
	key, err := intcom.SampleCommitmentKey(uint(keyLen), pcg.NewRandomised())
	require.NoError(tb, err, "failed to sample commitment key")
	return &properties.MessageProperties[*intcom.Message]{
		MessageGenerator: MessageGenerator(tb, key),
		MessagesAreEqual: func(m1, m2 *intcom.Message) bool {
			return m1.Equal(m2)
		},
	}
}

func CommitmentPropertySuite(tb testing.TB, keyLen int) *properties.CommitmentProperties[*intcom.Commitment] {
	tb.Helper()
	key, err := intcom.SampleCommitmentKey(uint(keyLen), pcg.NewRandomised())
	require.NoError(tb, err, "failed to sample commitment key")
	return &properties.CommitmentProperties[*intcom.Commitment]{
		CommitmentGenerator: CommitmentGenerator(tb, key),
		CommitmentsAreEqual: func(c1, c2 *intcom.Commitment) bool {
			return c1.Equal(c2)
		},
	}
}

func TestCommitmentKeyProperties(t *testing.T) {
	t.Parallel()
	t.Run("64-bit key", CommitmentKeyPropertySuite(t, 64).CheckAll)
}

func TestTrapdoorKeyProperties(t *testing.T) {
	t.Parallel()
	t.Run("64-bit key", TrapdoorKeyPropertySuite(t, 64).CheckAll)
}

func TestWitnessProperties(t *testing.T) {
	t.Parallel()
	t.Run("64-bit key", WitnessPropertySuite(t, 64).CheckAll)
}

func TestMessageProperties(t *testing.T) {
	t.Parallel()
	t.Run("64-bit key", MessagePropertySuite(t, 64).CheckAll)
}

func TestCommitmentProperties(t *testing.T) {
	t.Parallel()
	t.Run("64-bit key", CommitmentPropertySuite(t, 64).CheckAll)
}

func TestNoExponentReductionProperty(t *testing.T) {
	t.Parallel()
	keyLen := 64
	rapid.MakeCheck(func(rt *rapid.T) {
		key := CommitmentKeyGenerator(t, keyLen).Draw(rt, "commitment key")
		message := MessageGenerator(t, key).Draw(rt, "message")
		witness, err := key.SampleWitness(pcg.NewRandomised())
		require.NoError(rt, err, "failed to sample witness")
		commitment, err := key.CommitWithWitness(message, witness)
		require.NoError(rt, err, "failed to compute commitment")

		modulus := key.Group().Modulus()
		shiftedMessage, err := intcom.NewMessage(message.Value().Add(modulus.Lift()))
		require.NoError(rt, err, "failed to create shifted message")

		commitmentWithShiftedMessage, err := key.CommitWithWitness(shiftedMessage, witness)
		require.NoError(rt, err, "failed to compute commitment with shifted message")

		require.False(t, commitment.Equal(commitmentWithShiftedMessage), "commitments should not be equal when message is shifted by modulus")
	})
}

func TestFreshWitnessIsWithinRange(t *testing.T) {
	t.Parallel()
	keyLen := 64
	rapid.MakeCheck(func(rt *rapid.T) {
		key := CommitmentKeyGenerator(t, keyLen).Draw(rt, "commitment key")
		witness, err := key.SampleWitness(pcg.NewRandomised())
		require.NoError(rt, err, "failed to sample witness")
		require.True(t, key.WitnessIsFreshlySampled(witness))
	})
}
