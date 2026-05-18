package paillier_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/prng"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/encryption/testutils"
	"github.com/bronlabs/bron-crypto/pkg/encryption/testutils/properties"
)

func decryptionKeyGenerator(tb testing.TB, keyLen int, sampler func(keyLen uint, prng io.Reader) (*paillier.SecretKey, error)) *rapid.Generator[*paillier.SecretKey] {
	tb.Helper()
	return rapid.Custom(func(rt *rapid.T) *paillier.SecretKey {
		seed := rapid.Uint64().Draw(rt, "seed")
		salt := rapid.Uint64().Draw(rt, "salt")
		prng := pcg.New(seed, salt)
		key, err := sampler(uint(keyLen), prng)
		require.NoError(rt, err)
		return key
	})
}

func DecryptionKeyGenerator(tb testing.TB, keyLen int) *rapid.Generator[*paillier.SecretKey] {
	tb.Helper()

	return decryptionKeyGenerator(tb, keyLen, paillier.SampleSecretKey)
}

func PaillierBlumDecryptionKeyGenerator(tb testing.TB, keyLen int) *rapid.Generator[*paillier.SecretKey] {
	tb.Helper()
	return decryptionKeyGenerator(tb, keyLen, paillier.SampleBlumSecretKey)
}

func SafeDecryptionKeyGenerator(tb testing.TB, keyLen int) *rapid.Generator[*paillier.SecretKey] {
	tb.Helper()
	return decryptionKeyGenerator(tb, keyLen, paillier.SampleSafeSecretKey)
}

func CiphertextGenerator(tb testing.TB, key testutils.TypeErasedEncryptionKey[*paillier.Plaintext, *paillier.Nonce, *paillier.Ciphertext]) *rapid.Generator[*paillier.Ciphertext] {
	tb.Helper()
	obj, ok := key.(interface {
		CiphertextGroup() *znstar.PaillierGroupUnknownOrder
	})
	require.True(tb, ok, "encryption key must have a CiphertextGroup method")
	return rapid.Custom(func(rt *rapid.T) *paillier.Ciphertext {
		seed := rapid.Uint64().Draw(rt, "seed")
		salt := rapid.Uint64().Draw(rt, "salt")
		prng := pcg.New(seed, salt)
		c, err := obj.CiphertextGroup().Random(prng)
		require.NoError(rt, err)
		out, err := paillier.NewCiphertextFromGroupElement(c)
		require.NoError(rt, err)
		return out
	})
}

func NonceGenerator(tb testing.TB, key testutils.TypeErasedEncryptionKey[*paillier.Plaintext, *paillier.Nonce, *paillier.Ciphertext]) *rapid.Generator[*paillier.Nonce] {
	tb.Helper()
	obj, ok := key.(interface {
		NonceGroup() *znstar.RSAGroupUnknownOrder
	})
	require.True(tb, ok, "encryption key must have a NonceGroup method")
	return rapid.Custom(func(rt *rapid.T) *paillier.Nonce {
		seed := rapid.Uint64().Draw(rt, "seed")
		salt := rapid.Uint64().Draw(rt, "salt")
		prng := pcg.New(seed, salt)
		r, err := obj.NonceGroup().Random(prng)
		require.NoError(rt, err)
		out, err := paillier.NewNonceFromGroupElement(r)
		require.NoError(rt, err)
		return out
	})
}

func PlaintextGenerator(tb testing.TB, key testutils.TypeErasedEncryptionKey[*paillier.Plaintext, *paillier.Nonce, *paillier.Ciphertext]) *rapid.Generator[*paillier.Plaintext] {
	tb.Helper()
	obj, ok := key.(interface {
		PlaintextGroup() *num.ZMod
	})
	require.True(tb, ok, "encryption key must have a PlaintextGroup method")
	return rapid.Custom(func(rt *rapid.T) *paillier.Plaintext {
		seed := rapid.Uint64().Draw(rt, "seed")
		salt := rapid.Uint64().Draw(rt, "salt")
		prng := pcg.New(seed, salt)
		m, err := obj.PlaintextGroup().Random(prng)
		require.NoError(rt, err)
		out, err := paillier.NewPlaintext(m)
		require.NoError(rt, err)
		return out
	})
}

func ScalarGenerator(tb testing.TB, key testutils.TypeErasedHomomorphicEncryptionKey[*paillier.Plaintext, *paillier.Nonce, *paillier.Ciphertext, *num.Int]) *rapid.Generator[*num.Int] {
	tb.Helper()
	obj, ok := key.(interface {
		CiphertextGroup() *znstar.PaillierGroupUnknownOrder
	})
	require.True(tb, ok, "encryption key must have a CiphertextGroup method")
	return rapid.Custom(func(rt *rapid.T) *num.Int {
		seed := rapid.Uint64().Draw(rt, "seed")
		salt := rapid.Uint64().Draw(rt, "salt")
		prng := pcg.New(seed, salt)
		modulus := obj.CiphertextGroup().Modulus()
		s, err := num.Z().Random(modulus.Lift().Neg(), modulus.Lift(), prng)
		require.NoError(rt, err)
		return s
	})
}

type GroupHomomorphicEncryptionProperties = properties.GroupHomomorphicEncryptionProperties[
	*paillier.SecretKey,
	*paillier.PublicKey,
	*paillier.Plaintext, *num.ZMod, *num.Uint,
	*paillier.Nonce, *znstar.RSAGroupUnknownOrder, *znstar.RSAGroupElementUnknownOrder,
	*paillier.Ciphertext, *znstar.PaillierGroupUnknownOrder, *znstar.PaillierGroupElementUnknownOrder,
	*num.Int,
]

func encryptionPropertySuite(
	tb testing.TB,
	selfEncrypt bool,
	keyLen int,
	decryptionKeyGeneratorFunc func(tb testing.TB, keyLen int) *rapid.Generator[*paillier.SecretKey],
) *GroupHomomorphicEncryptionProperties {
	tb.Helper()
	require.NotNil(tb, decryptionKeyGeneratorFunc, "decryption key generator function must not be nil")
	return properties.NewGroupHomomorphicEncryptionProperties(
		tb,
		prng.FuncTypeErase(pcg.NewRandomised),
		selfEncrypt,
		true,
		decryptionKeyGeneratorFunc(tb, keyLen),
		PlaintextGenerator,
		func(p1, p2 *paillier.Plaintext) bool { return p1.Equal(p2) },
		func(n1, n2 *paillier.Nonce) bool { return n1.Equal(n2) },
		ScalarGenerator,
		CiphertextGenerator,
		paillier.NewPlaintext,
		paillier.NewNonceFromGroupElement,
		paillier.NewCiphertextFromGroupElement,
		func(tb testing.TB, plaintext *paillier.Plaintext, scalar *num.Int) *paillier.Plaintext {
			tb.Helper()
			out, err := paillier.NewPlaintext(plaintext.Value().Mul(scalar.Mod(plaintext.Group().Modulus())))
			require.NoError(tb, err)
			return out
		},
		func(tb testing.TB, nonce *paillier.Nonce, scalar *num.Int) *paillier.Nonce {
			tb.Helper()
			out, err := paillier.NewNonceFromGroupElement(nonce.Value().ScalarOp(scalar))
			require.NoError(tb, err)
			return out
		},
		func(tb testing.TB, ciphertext *paillier.Ciphertext, scalar *num.Int) *paillier.Ciphertext {
			tb.Helper()
			out, err := paillier.NewCiphertextFromGroupElement(ciphertext.Value().ScalarOp(scalar))
			require.NoError(tb, err)
			return out
		},
	)
}

func EncryptionPropertySuite(tb testing.TB, keyLen int) *GroupHomomorphicEncryptionProperties {
	tb.Helper()
	return encryptionPropertySuite(tb, false, keyLen, DecryptionKeyGenerator)
}

func SelfEncryptionPropertySuite(tb testing.TB, keyLen int) *GroupHomomorphicEncryptionProperties {
	tb.Helper()
	return encryptionPropertySuite(tb, true, keyLen, DecryptionKeyGenerator)
}

func PaillierBlumEncryptionPropertySuite(tb testing.TB, keyLen int) *GroupHomomorphicEncryptionProperties {
	tb.Helper()
	return encryptionPropertySuite(tb, false, keyLen, PaillierBlumDecryptionKeyGenerator)
}

func PaillierBlumSelfEncryptionPropertySuite(tb testing.TB, keyLen int) *GroupHomomorphicEncryptionProperties {
	tb.Helper()
	return encryptionPropertySuite(tb, true, keyLen, PaillierBlumDecryptionKeyGenerator)
}

func SafeEncryptionPropertySuite(tb testing.TB, keyLen int) *GroupHomomorphicEncryptionProperties {
	tb.Helper()
	return encryptionPropertySuite(tb, false, keyLen, SafeDecryptionKeyGenerator)
}

func SafeSelfEncryptionPropertySuite(tb testing.TB, keyLen int) *GroupHomomorphicEncryptionProperties {
	tb.Helper()
	return encryptionPropertySuite(tb, true, keyLen, SafeDecryptionKeyGenerator)
}

func NoncePropertySuite(tb testing.TB, keyLen int) *properties.NonceProperties[*paillier.Nonce] {
	tb.Helper()
	key, err := paillier.SampleSecretKey(uint(keyLen), pcg.NewRandomised())
	require.NoError(tb, err)
	return &properties.NonceProperties[*paillier.Nonce]{
		NonceGenerator: NonceGenerator(tb, key),
		NoncesAreEqual: func(n1, n2 *paillier.Nonce) bool { return n1.Equal(n2) },
	}
}

func PlaintextPropertySuite(tb testing.TB, keyLen int) *properties.PlaintextProperties[*paillier.Plaintext] {
	tb.Helper()
	key, err := paillier.SampleSecretKey(uint(keyLen), pcg.NewRandomised())
	require.NoError(tb, err)
	return &properties.PlaintextProperties[*paillier.Plaintext]{
		PlaintextGenerator: PlaintextGenerator(tb, key),
		PlaintextsAreEqual: func(p1, p2 *paillier.Plaintext) bool { return p1.Equal(p2) },
	}
}

func CiphertextPropertySuite(tb testing.TB, keyLen int) *properties.CiphertextProperties[*paillier.Ciphertext] {
	tb.Helper()
	key, err := paillier.SampleSecretKey(uint(keyLen), pcg.NewRandomised())
	require.NoError(tb, err)
	return &properties.CiphertextProperties[*paillier.Ciphertext]{
		CiphertextGenerator: CiphertextGenerator(tb, key),
		CiphertextsAreEqual: func(c1, c2 *paillier.Ciphertext) bool { return c1.Equal(c2) },
	}
}

func TestEncryptionProperties(t *testing.T) {
	t.Parallel()
	t.Run("64-bit key", EncryptionPropertySuite(t, 64).CheckAll)
}

func TestSelfEncryptionProperties(t *testing.T) {
	t.Parallel()
	t.Run("64-bit key", SelfEncryptionPropertySuite(t, 64).CheckAll)
}

func TestPaillierBlumEncryptionProperties(t *testing.T) {
	t.Parallel()
	t.Run("64-bit key", PaillierBlumEncryptionPropertySuite(t, 64).CheckAll)
}

func TestPaillierBlumSelfEncryptionProperties(t *testing.T) {
	t.Parallel()
	t.Run("64-bit key", PaillierBlumSelfEncryptionPropertySuite(t, 64).CheckAll)
}

func TestSafeEncryptionProperties(t *testing.T) {
	t.Parallel()
	t.Run("64-bit key", SafeEncryptionPropertySuite(t, 64).CheckAll)
}

func TestSafeSelfEncryptionProperties(t *testing.T) {
	t.Parallel()
	t.Run("64-bit key", SafeSelfEncryptionPropertySuite(t, 64).CheckAll)
}

func TestNonceProperties(t *testing.T) {
	t.Parallel()
	t.Run("1024-bit key", NoncePropertySuite(t, 1024).CheckAll)
}

func TestPlaintextProperties(t *testing.T) {
	t.Parallel()
	t.Run("1024-bit key", PlaintextPropertySuite(t, 1024).CheckAll)
}

func TestCiphertextProperties(t *testing.T) {
	t.Parallel()
	t.Run("1024-bit key", CiphertextPropertySuite(t, 1024).CheckAll)
}

func TestGroupsHaveCorrectModuliProperty(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		keyLen := rapid.OneOf(
			rapid.Just(64),
			rapid.Just(128),
			rapid.Just(256),
		).Draw(rt, "keyLen")
		key := rapid.OneOf(
			DecryptionKeyGenerator(t, keyLen),
			PaillierBlumDecryptionKeyGenerator(t, keyLen),
			SafeDecryptionKeyGenerator(t, keyLen),
		).Draw(rt, "decryptionKey")
		ciphertextGroup := key.CiphertextGroup()
		nonceGroup := key.NonceGroup()
		plaintextGroup := key.PlaintextGroup()

		require.True(rt, ciphertextGroup.N().Equal(nonceGroup.Modulus()), "ciphertext group modulus must equal nonce group modulus")
		require.True(rt, plaintextGroup.Modulus().Equal(nonceGroup.Modulus()), "plaintext group modulus must equal nonce group modulus")
	})
}

func TestEncryptDecryptRoundtripWithSymmetricPlaintextsProperty(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		keyLen := rapid.OneOf(
			rapid.Just(64),
			rapid.Just(128),
			rapid.Just(256),
		).Draw(rt, "keyLen")

		decryptionKey := rapid.OneOf(
			DecryptionKeyGenerator(t, keyLen),
			PaillierBlumDecryptionKeyGenerator(t, keyLen),
			SafeDecryptionKeyGenerator(t, keyLen),
		).Draw(rt, "decryptionKey")

		selfEncrypt := rapid.Bool().Draw(rt, "selfEncrypt")

		symmetricValue := rapid.Map(
			rapid.IntRange(-(keyLen-1)/2, (keyLen-1)/2),
			func(i int) *num.Int { return num.Z().FromInt64(int64(i)) },
		).Draw(rt, "symmetricValue")

		plaintext, err := paillier.NewPlaintextSymmetric(symmetricValue, decryptionKey.PlaintextGroup().Modulus())
		require.NoError(rt, err)

		nonce, err := decryptionKey.SampleNonce(pcg.NewRandomised())
		require.NoError(rt, err)

		var ciphertext *paillier.Ciphertext

		if selfEncrypt {
			ciphertext, err = decryptionKey.EncryptWithNonce(plaintext, nonce)
		} else {
			ciphertext, err = decryptionKey.Public().EncryptWithNonce(plaintext, nonce)
		}
		require.NoError(rt, err)

		decryptedPlaintext, err := decryptionKey.Decrypt(ciphertext)
		require.NoError(rt, err)

		require.True(rt, plaintext.Equal(decryptedPlaintext), "decrypted plaintext must equal original plaintext")
	})
}
