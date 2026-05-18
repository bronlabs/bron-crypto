package elgamal_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
	"github.com/bronlabs/bron-crypto/pkg/encryption/testutils"
	"github.com/bronlabs/bron-crypto/pkg/encryption/testutils/properties"
)

func DecryptionKeyGenerator[E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]](
	tb testing.TB, group elgamal.FiniteCyclicGroup[E, S],
) *rapid.Generator[*elgamal.SecretKey[E, S]] {
	tb.Helper()
	return rapid.Custom(func(rt *rapid.T) *elgamal.SecretKey[E, S] {
		seed := rapid.Uint64().Draw(rt, "seed")
		salt := rapid.Uint64().Draw(rt, "salt")
		prng := pcg.New(seed, salt)
		key, err := elgamal.SampleSecretKey(group, prng)
		require.NoError(rt, err)
		return key
	})
}

func CiphertextGenerator[E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]](
	tb testing.TB, key testutils.TypeErasedEncryptionKey[*elgamal.Plaintext[E, S], *elgamal.Nonce[S], *elgamal.Ciphertext[E, S]],
) *rapid.Generator[*elgamal.Ciphertext[E, S]] {
	tb.Helper()
	obj, ok := key.(interface {
		CiphertextGroup() *constructions.FiniteDirectPowerModule[elgamal.FiniteCyclicGroup[E, S], E, S]
	})
	require.True(tb, ok, "encryption key does not have CiphertextGroup method")
	return rapid.Custom(func(rt *rapid.T) *elgamal.Ciphertext[E, S] {
		seed := rapid.Uint64().Draw(rt, "seed")
		salt := rapid.Uint64().Draw(rt, "salt")
		prng := pcg.New(seed, salt)
		c, err := obj.CiphertextGroup().Random(prng)
		require.NoError(rt, err)
		out, err := elgamal.NewCiphertextFromGroupElement(c)
		require.NoError(rt, err)
		return out
	})
}

func NonceGenerator[E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]](
	tb testing.TB, key testutils.TypeErasedEncryptionKey[*elgamal.Plaintext[E, S], *elgamal.Nonce[S], *elgamal.Ciphertext[E, S]],
) *rapid.Generator[*elgamal.Nonce[S]] {
	tb.Helper()
	obj, ok := key.(interface {
		NonceGroup() algebra.ZModLike[S]
	})
	require.True(tb, ok, "encryption key does not have NonceGroup method")
	return rapid.Custom(func(rt *rapid.T) *elgamal.Nonce[S] {
		seed := rapid.Uint64().Draw(rt, "seed")
		salt := rapid.Uint64().Draw(rt, "salt")
		prng := pcg.New(seed, salt)
		n, err := obj.NonceGroup().Random(prng)
		require.NoError(rt, err)
		out, err := elgamal.NewNonce(n)
		require.NoError(rt, err)
		return out
	})
}

func PlaintextGenerator[E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]](
	tb testing.TB, key testutils.TypeErasedEncryptionKey[*elgamal.Plaintext[E, S], *elgamal.Nonce[S], *elgamal.Ciphertext[E, S]],
) *rapid.Generator[*elgamal.Plaintext[E, S]] {
	tb.Helper()
	obj, ok := key.(interface {
		PlaintextGroup() elgamal.FiniteCyclicGroup[E, S]
	})
	require.True(tb, ok, "encryption key does not have PlaintextGroup method")
	return rapid.Custom(func(rt *rapid.T) *elgamal.Plaintext[E, S] {
		seed := rapid.Uint64().Draw(rt, "seed")
		salt := rapid.Uint64().Draw(rt, "salt")
		prng := pcg.New(seed, salt)
		m, err := obj.PlaintextGroup().Random(prng)
		require.NoError(rt, err)
		out, err := elgamal.NewPlaintext(m)
		require.NoError(rt, err)
		return out
	})
}

func ScalarGenerator[E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]](
	tb testing.TB, key testutils.TypeErasedHomomorphicEncryptionKey[*elgamal.Plaintext[E, S], *elgamal.Nonce[S], *elgamal.Ciphertext[E, S], S],
) *rapid.Generator[S] {
	tb.Helper()
	obj, ok := key.(interface {
		NonceGroup() algebra.ZModLike[S]
	})
	require.True(tb, ok, "encryption key does not have NonceGroup method")
	return rapid.Custom(func(rt *rapid.T) S {
		seed := rapid.Uint64().Draw(rt, "seed")
		salt := rapid.Uint64().Draw(rt, "salt")
		prng := pcg.New(seed, salt)
		s, err := obj.NonceGroup().Random(prng)
		require.NoError(rt, err)
		return s
	})
}

type GroupHomomorphicEncryptionProperties[E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]] = properties.GroupHomomorphicEncryptionProperties[
	*elgamal.SecretKey[E, S],
	*elgamal.PublicKey[E, S],
	*elgamal.Plaintext[E, S], elgamal.FiniteCyclicGroup[E, S], E,
	*elgamal.Nonce[S], algebra.ZModLike[S], S,
	*elgamal.Ciphertext[E, S], *constructions.FiniteDirectPowerModule[elgamal.FiniteCyclicGroup[E, S], E, S], *constructions.FiniteDirectPowerModuleElement[E, S],
	S,
]

func encryptionPropertySuite[E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]](
	tb testing.TB, group elgamal.FiniteCyclicGroup[E, S], selfEncrypt bool,
) *GroupHomomorphicEncryptionProperties[E, S] {
	tb.Helper()
	return properties.NewGroupHomomorphicEncryptionProperties(
		tb,
		prng.FuncTypeErase(pcg.NewRandomised),
		selfEncrypt,
		false,
		DecryptionKeyGenerator(tb, group),
		PlaintextGenerator,
		func(p1, p2 *elgamal.Plaintext[E, S]) bool { return p1.Equal(p2) },
		func(n1, n2 *elgamal.Nonce[S]) bool { return n1.Equal(n2) },
		ScalarGenerator,
		CiphertextGenerator,
		elgamal.NewPlaintext,
		elgamal.NewNonce,
		elgamal.NewCiphertextFromGroupElement,
		func(tb testing.TB, plaintext *elgamal.Plaintext[E, S], scalar S) *elgamal.Plaintext[E, S] {
			tb.Helper()
			out, err := elgamal.NewPlaintext(plaintext.Value().ScalarOp(scalar))
			require.NoError(tb, err)
			return out
		},
		func(tb testing.TB, nonce *elgamal.Nonce[S], scalar S) *elgamal.Nonce[S] {
			tb.Helper()
			out, err := elgamal.NewNonce(nonce.Value().Mul(scalar))
			require.NoError(tb, err)
			return out
		},
		func(tb testing.TB, ciphertext *elgamal.Ciphertext[E, S], scalar S) *elgamal.Ciphertext[E, S] {
			tb.Helper()
			out, err := elgamal.NewCiphertextFromGroupElement(ciphertext.Value().ScalarOp(scalar))
			require.NoError(tb, err)
			return out
		},
	)
}

func EncryptionPropertySuite[E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]](tb testing.TB, group elgamal.FiniteCyclicGroup[E, S]) *GroupHomomorphicEncryptionProperties[E, S] {
	tb.Helper()
	return encryptionPropertySuite(tb, group, false)
}

func SelfEncryptionPropertySuite[E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]](tb testing.TB, group elgamal.FiniteCyclicGroup[E, S]) *GroupHomomorphicEncryptionProperties[E, S] {
	tb.Helper()
	return encryptionPropertySuite(tb, group, true)
}

func NoncePropertySuite[E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]](tb testing.TB, group elgamal.FiniteCyclicGroup[E, S]) *properties.NonceProperties[*elgamal.Nonce[S]] {
	tb.Helper()
	key, err := elgamal.SampleSecretKey(group, pcg.NewRandomised())
	require.NoError(tb, err)
	return &properties.NonceProperties[*elgamal.Nonce[S]]{
		NonceGenerator: NonceGenerator(tb, key),
		NoncesAreEqual: func(n1, n2 *elgamal.Nonce[S]) bool { return n1.Equal(n2) },
	}
}

func PlaintextPropertySuite[E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]](tb testing.TB, group elgamal.FiniteCyclicGroup[E, S]) *properties.PlaintextProperties[*elgamal.Plaintext[E, S]] {
	tb.Helper()
	key, err := elgamal.SampleSecretKey(group, pcg.NewRandomised())
	require.NoError(tb, err)
	return &properties.PlaintextProperties[*elgamal.Plaintext[E, S]]{
		PlaintextGenerator: PlaintextGenerator(tb, key),
		PlaintextsAreEqual: func(p1, p2 *elgamal.Plaintext[E, S]) bool { return p1.Equal(p2) },
	}
}

func CiphertextPropertySuite[E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]](tb testing.TB, group elgamal.FiniteCyclicGroup[E, S]) *properties.CiphertextProperties[*elgamal.Ciphertext[E, S]] {
	tb.Helper()
	key, err := elgamal.SampleSecretKey(group, pcg.NewRandomised())
	require.NoError(tb, err)
	return &properties.CiphertextProperties[*elgamal.Ciphertext[E, S]]{
		CiphertextGenerator: CiphertextGenerator(tb, key),
		CiphertextsAreEqual: func(c1, c2 *elgamal.Ciphertext[E, S]) bool { return c1.Equal(c2) },
	}
}

func TestEncryptionProperties(t *testing.T) {
	t.Parallel()
	t.Run("k256", EncryptionPropertySuite(t, k256.NewCurve()).CheckAll)
}

func TestSelfEncryptionProperties(t *testing.T) {
	t.Parallel()
	t.Run("k256", SelfEncryptionPropertySuite(t, k256.NewCurve()).CheckAll)
}

func TestNonceProperties(t *testing.T) {
	t.Parallel()
	t.Run("k256", NoncePropertySuite(t, k256.NewCurve()).CheckAll)
}

func TestPlaintextProperties(t *testing.T) {
	t.Parallel()
	t.Run("k256", PlaintextPropertySuite(t, k256.NewCurve()).CheckAll)
}

func TestCiphertextProperties(t *testing.T) {
	t.Parallel()
	t.Run("k256", CiphertextPropertySuite(t, k256.NewCurve()).CheckAll)
}
