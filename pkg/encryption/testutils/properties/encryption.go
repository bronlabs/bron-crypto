package properties

import (
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	serdeprop "github.com/bronlabs/bron-crypto/pkg/base/serde/testutils/properties"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/testutils"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func NewEncryptionProperties[
	DK encryption.DecryptionKey[EK, DK, P, N, C], EK encryption.EncryptionKey[EK, P, N, C], P encryption.Plaintext, N encryption.Nonce, C encryption.Ciphertext[C],
](
	tb testing.TB,
	prng func() io.Reader,
	selfEncrypt bool,
	openable bool,
	decryptionKeyGenerator *rapid.Generator[DK],
	plaintextGenerator func(testing.TB, testutils.TypeErasedEncryptionKey[P, N, C]) *rapid.Generator[P],
	plaintextsAreEqual func(P, P) bool,
	noncesAreEqual func(N, N) bool,
) *EncryptionProperties[DK, EK, P, N, C] {
	tb.Helper()
	require.NotNil(tb, prng, "prng must not be nil")
	require.NotNil(tb, decryptionKeyGenerator, "decryptionKeyGenerator must not be nil")
	require.NotNil(tb, plaintextGenerator, "plaintextGenerator must not be nil")
	require.NotNil(tb, plaintextsAreEqual, "plaintextsAreEqual must not be nil")
	require.NotNil(tb, noncesAreEqual, "noncesAreEqual must not be nil")
	return &EncryptionProperties[DK, EK, P, N, C]{
		PRNG:                   prng,
		DecryptionKeyGenerator: decryptionKeyGenerator,
		PlaintextGenerator:     plaintextGenerator,
		SelfEncrypt:            selfEncrypt,
		Openable:               openable,
		PlaintextsAreEqual:     plaintextsAreEqual,
		NoncesAreEqual:         noncesAreEqual,
	}
}

type EncryptionProperties[DK encryption.DecryptionKey[EK, DK, P, N, C], EK encryption.EncryptionKey[EK, P, N, C], P encryption.Plaintext, N encryption.Nonce, C encryption.Ciphertext[C]] struct {
	PRNG                   func() io.Reader
	DecryptionKeyGenerator *rapid.Generator[DK]
	PlaintextGenerator     func(testing.TB, testutils.TypeErasedEncryptionKey[P, N, C]) *rapid.Generator[P]

	SelfEncrypt bool
	Openable    bool

	PlaintextsAreEqual func(P, P) bool
	NoncesAreEqual     func(N, N) bool
}

func (pr *EncryptionProperties[DK, EK, P, N, C]) getEncryptionKey(tb testing.TB, dk DK) testutils.TypeErasedEncryptionKey[P, N, C] {
	tb.Helper()
	var out testutils.TypeErasedEncryptionKey[P, N, C]
	var ok bool
	if pr.SelfEncrypt {
		out, ok = any(dk).(encryption.EncryptionKey[DK, P, N, C])
		require.True(tb, ok, "decryption key must also implement EncryptionKey")
	} else {
		out = dk.Public()
	}
	return out
}

func (pr *EncryptionProperties[DK, EK, P, N, C]) opener(tb testing.TB, dk DK) interface {
	Open(C) (P, N, error)
} {
	tb.Helper()
	require.True(tb, pr.Openable, "cannot open ciphertexts with this properties suite")
	opener, ok := any(dk).(interface {
		Open(C) (P, N, error)
	})
	require.True(tb, ok, "decryption key must also implement OpeningKey to use open helper")
	return opener
}

func (pr *EncryptionProperties[DK, EK, P, N, C]) CheckAll(t *testing.T) {
	t.Parallel()
	t.Run("EncryptionKeyIsCBORSerialisable", pr.EncryptionKeyIsCBORSerialisable)
	t.Run("DecryptionKeyIsCBORSerialisable", pr.DecryptionKeyIsCBORSerialisable)
	t.Run("EncryptDecryptOpenRoundtrip", pr.EncryptDecryptOpenRoundtrip)
	t.Run("DeterminismGivenExplicitRandomness", pr.DeterminismGivenExplicitRandomness)
	t.Run("DifferentNonceSamePlaintextDifferentCiphertext", pr.DifferentNonceSamePlaintextDifferentCiphertext)
	t.Run("DifferentPlaintextSameNonceDifferentCiphertext", pr.DifferentPlaintextSameNonceDifferentCiphertext)
	t.Run("EncryptingDoesntMutateAnything", pr.EncryptingDoesntMutateAnything)
	t.Run("DecryptingDoesntMutateAnything", pr.DecryptingDoesntMutateAnything)
	t.Run("OpeningDoesntMutateAnything", pr.OpeningDoesntMutateAnything)
	t.Run("EncryptHelperWorks", pr.EncryptHelperWorks)
	t.Run("EncryptManyHelperWorks", pr.EncryptManyHelperWorks)
	t.Run("EncryptManyWithNoncesHelperWorks", pr.EncryptManyWithNoncesHelperWorks)
	t.Run("DecryptManyHelperWorks", pr.DecryptManyHelperWorks)
	t.Run("OpenManyHelperWorks", pr.OpenManyHelperWorks)
}

func (pr *EncryptionProperties[DK, EK, P, N, C]) EncryptionKeyIsCBORSerialisable(t *testing.T) {
	serialisationSuite := serdeprop.SerialisationProperties[EK]{
		Generator: rapid.Map(pr.DecryptionKeyGenerator, func(sk DK) EK { return sk.Public() }),
		AreEqual:  func(k1, k2 EK) bool { return k1.Equal(k2) },
	}
	serialisationSuite.CheckAll(t)
}

func (pr *EncryptionProperties[DK, EK, P, N, C]) DecryptionKeyIsCBORSerialisable(t *testing.T) {
	serialisationSuite := serdeprop.SerialisationProperties[DK]{
		Generator: pr.DecryptionKeyGenerator,
		AreEqual:  func(k1, k2 DK) bool { return k1.Equal(k2) },
	}
	serialisationSuite.CheckAll(t)
}

func (pr *EncryptionProperties[DK, EK, P, N, C]) EncryptDecryptOpenRoundtrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decryptionKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		encryptionKey := pr.getEncryptionKey(t, decryptionKey)
		plaintext := pr.PlaintextGenerator(t, encryptionKey).Draw(rt, "plaintext")
		nonce, err := encryptionKey.SampleNonce(pr.PRNG())
		require.NoError(rt, err)

		ciphertext, err := encryptionKey.EncryptWithNonce(plaintext, nonce)
		require.NoError(rt, err)

		decryptedPlaintext, err := decryptionKey.Decrypt(ciphertext)
		require.NoError(rt, err)

		require.True(rt, pr.PlaintextsAreEqual(plaintext, decryptedPlaintext), "Decrypted plaintext should be equal to original plaintext")

		if pr.Openable {
			openedPlaintext, openedNonce, err := pr.opener(t, decryptionKey).Open(ciphertext)
			require.NoError(rt, err)
			require.True(rt, pr.PlaintextsAreEqual(plaintext, openedPlaintext), "Opened plaintext should be equal to original plaintext")
			require.True(rt, pr.NoncesAreEqual(nonce, openedNonce), "Opened nonce should be equal to original nonce")
		}
	})
}

func (pr *EncryptionProperties[DK, EK, P, N, C]) DeterminismGivenExplicitRandomness(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decryptionKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decryptionKey)
		plaintext := pr.PlaintextGenerator(t, key).Draw(rt, "plaintext")
		nonce, err := key.SampleNonce(pr.PRNG())
		require.NoError(rt, err)

		c1, err := key.EncryptWithNonce(plaintext, nonce)
		require.NoError(rt, err)
		c2, err := key.EncryptWithNonce(plaintext, nonce)
		require.NoError(rt, err)

		require.True(rt, c1.Equal(c2), "Ciphertexts should be equal when encrypted with the same nonce and plaintext")
	})
}

func (pr *EncryptionProperties[DK, EK, P, N, C]) DifferentNonceSamePlaintextDifferentCiphertext(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decryptionKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decryptionKey)
		plaintext := pr.PlaintextGenerator(t, key).Draw(rt, "plaintext")
		nonce1, err := key.SampleNonce(pr.PRNG())
		require.NoError(rt, err)

		nonce2, err := key.SampleNonce(pr.PRNG())
		require.NoError(rt, err)

		for pr.NoncesAreEqual(nonce1, nonce2) {
			nonce2, err = key.SampleNonce(pr.PRNG())
			require.NoError(rt, err)
		}

		c1, err := key.EncryptWithNonce(plaintext, nonce1)
		require.NoError(rt, err)
		c2, err := key.EncryptWithNonce(plaintext, nonce2)
		require.NoError(rt, err)

		require.False(rt, c1.Equal(c2), "Ciphertexts should not be equal when encrypted with different nonces")
	})
}

func (pr *EncryptionProperties[DK, EK, P, N, C]) DifferentPlaintextSameNonceDifferentCiphertext(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decryptionKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decryptionKey)

		nonce, err := key.SampleNonce(pr.PRNG())
		require.NoError(rt, err)

		p1 := pr.PlaintextGenerator(t, key).Draw(rt, "plaintext 1")
		p2 := pr.PlaintextGenerator(t, key).Filter(func(p P) bool {
			return !pr.PlaintextsAreEqual(p1, p)
		}).Draw(rt, "plaintext 2")

		c1, err := key.EncryptWithNonce(p1, nonce)
		require.NoError(rt, err)
		c2, err := key.EncryptWithNonce(p2, nonce)
		require.NoError(rt, err)

		require.False(rt, c1.Equal(c2), "Ciphertexts should not be equal when encrypted with different plaintexts")
	})
}

func (pr *EncryptionProperties[DK, EK, P, N, C]) EncryptingDoesntMutateAnything(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decryptionKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decryptionKey)
		plaintext := pr.PlaintextGenerator(t, key).Draw(rt, "plaintext")

		nonce, err := key.SampleNonce(pr.PRNG())
		require.NoError(rt, err)

		keyMarshalled, err := serde.MarshalCBOR(key)
		require.NoError(rt, err)
		plaintextMarshalled, err := serde.MarshalCBOR(plaintext)
		require.NoError(rt, err)
		nonceMarshalled, err := serde.MarshalCBOR(nonce)
		require.NoError(rt, err)

		_, err = key.EncryptWithNonce(plaintext, nonce)
		require.NoError(rt, err)

		keyMarshalledAfter, err := serde.MarshalCBOR(key)
		require.NoError(rt, err)
		plaintextMarshalledAfter, err := serde.MarshalCBOR(plaintext)
		require.NoError(rt, err)
		nonceMarshalledAfter, err := serde.MarshalCBOR(nonce)
		require.NoError(rt, err)

		require.Equal(rt, keyMarshalled, keyMarshalledAfter, "Encryption should not mutate the key")
		require.Equal(rt, plaintextMarshalled, plaintextMarshalledAfter, "Encryption should not mutate the plaintext")
		require.Equal(rt, nonceMarshalled, nonceMarshalledAfter, "Encryption should not mutate the nonce")
	})
}

func (pr *EncryptionProperties[DK, EK, P, N, C]) DecryptingDoesntMutateAnything(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		encKey := pr.getEncryptionKey(t, decKey)
		plaintext := pr.PlaintextGenerator(t, encKey).Draw(rt, "plaintext")

		nonce, err := decKey.SampleNonce(pr.PRNG())
		require.NoError(rt, err)

		ciphertext, err := encKey.EncryptWithNonce(plaintext, nonce)
		require.NoError(rt, err)

		keyMarshalled, err := serde.MarshalCBOR(decKey)
		require.NoError(rt, err)
		ciphertextMarshalled, err := serde.MarshalCBOR(ciphertext)
		require.NoError(rt, err)

		_, err = decKey.Decrypt(ciphertext)
		require.NoError(rt, err)

		keyMarshalledAfter, err := serde.MarshalCBOR(decKey)
		require.NoError(rt, err)
		ciphertextMarshalledAfter, err := serde.MarshalCBOR(ciphertext)
		require.NoError(rt, err)

		require.Equal(rt, keyMarshalled, keyMarshalledAfter, "Decryption should not mutate the key")
		require.Equal(rt, ciphertextMarshalled, ciphertextMarshalledAfter, "Decryption should not mutate the ciphertext")
	})
}

func (pr *EncryptionProperties[DK, EK, P, N, C]) OpeningDoesntMutateAnything(t *testing.T) {
	t.Parallel()
	if !pr.Openable {
		t.Skip("Ciphertext opening is not supported with this properties suite")
	}
	rapid.Check(t, func(rt *rapid.T) {
		decKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		encKey := pr.getEncryptionKey(t, decKey)
		plaintext := pr.PlaintextGenerator(t, encKey).Draw(rt, "plaintext")

		nonce, err := decKey.SampleNonce(pr.PRNG())
		require.NoError(rt, err)

		ciphertext, err := encKey.EncryptWithNonce(plaintext, nonce)
		require.NoError(rt, err)

		keyMarshalled, err := serde.MarshalCBOR(decKey)
		require.NoError(rt, err)
		ciphertextMarshalled, err := serde.MarshalCBOR(ciphertext)
		require.NoError(rt, err)

		_, _, err = pr.opener(t, decKey).Open(ciphertext)
		require.NoError(rt, err)

		keyMarshalledAfter, err := serde.MarshalCBOR(decKey)
		require.NoError(rt, err)
		ciphertextMarshalledAfter, err := serde.MarshalCBOR(ciphertext)
		require.NoError(rt, err)

		require.Equal(rt, keyMarshalled, keyMarshalledAfter, "Opening should not mutate the key")
		require.Equal(rt, ciphertextMarshalled, ciphertextMarshalledAfter, "Opening should not mutate the ciphertext")
	})

}

func (pr *EncryptionProperties[DK, EK, P, N, C]) EncryptHelperWorks(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decryptionKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decryptionKey)
		plaintext := pr.PlaintextGenerator(t, key).Draw(rt, "plaintext")

		c, n, err := encryption.Encrypt(plaintext, key, pr.PRNG())
		require.NoError(rt, err)

		cwn, err := key.EncryptWithNonce(plaintext, n)
		require.NoError(rt, err)

		require.True(rt, c.Equal(cwn), "Encrypt should produce the same ciphertext as EncryptWithNonce when using the same nonce")

	})
}

func (pr *EncryptionProperties[DK, EK, P, N, C]) EncryptManyHelperWorks(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decryptionKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decryptionKey)
		plaintexts := rapid.SliceOfN(pr.PlaintextGenerator(t, key), 2, 10).Draw(rt, "plaintexts")
		ciphertexts, nonces, err := encryption.EncryptMany(plaintexts, key, pr.PRNG())
		require.NoError(rt, err)

		for i, pi := range plaintexts {
			ci, err := key.EncryptWithNonce(pi, nonces[i])
			require.NoError(rt, err)
			require.True(rt, ciphertexts[i].Equal(ci), "EncryptMany should produce the same ciphertexts as EncryptWithNonce when using the same nonces")
		}
	})
}

func (pr *EncryptionProperties[DK, EK, P, N, C]) EncryptManyWithNoncesHelperWorks(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decryptionKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decryptionKey)
		plaintexts := rapid.SliceOfN(pr.PlaintextGenerator(t, key), 2, 10).Draw(rt, "plaintexts")
		nonces := make([]N, len(plaintexts))
		for i := range nonces {
			var err error
			nonces[i], err = key.SampleNonce(pr.PRNG())
			require.NoError(rt, err)
		}
		ciphertexts, err := encryption.EncryptManyWithNonces(plaintexts, key, nonces)
		require.NoError(rt, err)
		for i, pi := range plaintexts {
			ci, err := key.EncryptWithNonce(pi, nonces[i])
			require.NoError(rt, err)
			require.True(rt, ciphertexts[i].Equal(ci), "EncryptManyWithNonces should produce the same ciphertexts as EncryptWithNonce when using the same nonces")
		}
	})
}

func (pr *EncryptionProperties[DK, EK, P, N, C]) DecryptManyHelperWorks(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decryptionKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decryptionKey)
		plaintexts := rapid.SliceOfN(pr.PlaintextGenerator(t, key), 2, 10).Draw(rt, "plaintexts")
		ciphertexts, _, err := encryption.EncryptMany(plaintexts, key, pr.PRNG())
		require.NoError(rt, err)

		decryptedPlaintexts, err := encryption.DecryptMany(ciphertexts, decryptionKey)
		require.NoError(rt, err)

		for i := range plaintexts {
			require.True(rt, pr.PlaintextsAreEqual(plaintexts[i], decryptedPlaintexts[i]), "DecryptMany should produce the same plaintexts as Decrypt when decrypting the same ciphertexts")
		}
	})
}

func (pr *EncryptionProperties[DK, EK, P, N, C]) OpenManyHelperWorks(t *testing.T) {
	t.Parallel()
	if !pr.Openable {
		t.Skip("Ciphertext opening is not supported with this properties suite")
	}
	rapid.Check(t, func(rt *rapid.T) {
		decryptionKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decryptionKey)
		plaintexts := rapid.SliceOfN(pr.PlaintextGenerator(t, key), 2, 10).Draw(rt, "plaintexts")
		ciphertexts, nonces, err := encryption.EncryptMany(plaintexts, key, pr.PRNG())
		require.NoError(rt, err)

		for i, ci := range ciphertexts {
			pi, ni, err := pr.opener(t, decryptionKey).Open(ci)
			require.NoError(rt, err)
			require.True(rt, pr.PlaintextsAreEqual(plaintexts[i], pi), "OpenMany should produce the same plaintexts as Open when opening the same ciphertexts")
			require.True(rt, pr.NoncesAreEqual(nonces[i], ni), "OpenMany should produce the same nonces as Open when opening the same ciphertexts")
		}
	})
}

func NewHomomorphicEncryptionProperties[
	DK encryption.HomomorphicDecryptionKey[EK, DK, P, N, C, S],
	EK encryption.HomomorphicEncryptionKey[EK, P, N, C, S],
	P encryption.Plaintext,
	N encryption.Nonce,
	C encryption.Ciphertext[C],
	S any,
](
	tb testing.TB,
	prng func() io.Reader,
	selfEncrypt bool,
	openable bool,
	decryptionKeyGenerator *rapid.Generator[DK],
	plaintextGenerator func(testing.TB, testutils.TypeErasedEncryptionKey[P, N, C]) *rapid.Generator[P],
	plaintextsAreEqual func(P, P) bool,
	noncesAreEqual func(N, N) bool,
	scalarGenerator func(testing.TB, testutils.TypeErasedHomomorphicEncryptionKey[P, N, C, S]) *rapid.Generator[S],
) *HomomorphicEncryptionProperties[DK, EK, P, N, C, S] {
	tb.Helper()
	require.NotNil(tb, scalarGenerator, "scalarGenerator must not be nil")
	return &HomomorphicEncryptionProperties[DK, EK, P, N, C, S]{
		EncryptionProperties: *NewEncryptionProperties(tb, prng, selfEncrypt, openable, decryptionKeyGenerator, plaintextGenerator, plaintextsAreEqual, noncesAreEqual),
		ScalarGenerator:      scalarGenerator,
	}
}

type HomomorphicEncryptionProperties[
	DK encryption.HomomorphicDecryptionKey[EK, DK, P, N, C, S],
	EK encryption.HomomorphicEncryptionKey[EK, P, N, C, S],
	P encryption.Plaintext,
	N encryption.Nonce,
	C encryption.Ciphertext[C],
	S any,
] struct {
	EncryptionProperties[DK, EK, P, N, C]
	ScalarGenerator func(testing.TB, testutils.TypeErasedHomomorphicEncryptionKey[P, N, C, S]) *rapid.Generator[S]
}

func (pr *HomomorphicEncryptionProperties[DK, EK, P, N, C, S]) getEncryptionKey(tb testing.TB, dk DK) testutils.TypeErasedHomomorphicEncryptionKey[P, N, C, S] {
	tb.Helper()
	var out testutils.TypeErasedHomomorphicEncryptionKey[P, N, C, S]
	var ok bool
	if pr.SelfEncrypt {
		out, ok = any(dk).(encryption.HomomorphicEncryptionKey[DK, P, N, C, S])
		require.True(tb, ok, "decryption key must also implement HomomorphicEncryptionKey")
	} else {
		out = dk.Public()
	}
	return out
}

func (pr *HomomorphicEncryptionProperties[DK, EK, P, N, C, S]) CheckAll(t *testing.T) {
	t.Parallel()
	t.Run("EncryptionProperties", pr.EncryptionProperties.CheckAll)
	t.Run("CiphertextHomOpIsPlaintextNonceOp", pr.CiphertextHomOpIsPlaintextNonceOp)
	t.Run("DecryptingCiphertextHomOpMatchesPlaintextOp", pr.DecryptingCiphertextHomOpMatchesPlaintextOp)
	t.Run("CiphertextScalarOpIsPlaintextNonceScalarOp", pr.CiphertextScalarOpIsPlaintextNonceScalarOp)
	t.Run("ReRandomiseShiftsNonce", pr.ReRandomiseShiftsNonce)
	t.Run("CanShiftCiphertextByPlaintext", pr.CanShiftCiphertextByPlaintext)
}

func (pr *HomomorphicEncryptionProperties[DK, EK, P, N, C, S]) CiphertextHomOpIsPlaintextNonceOp(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decryptionKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decryptionKey)
		p1 := pr.PlaintextGenerator(t, key).Draw(rt, "plaintext 1")
		p2 := pr.PlaintextGenerator(t, key).Draw(rt, "plaintext 2")

		n1, err := key.SampleNonce(pr.PRNG())
		require.NoError(rt, err)
		n2, err := key.SampleNonce(pr.PRNG())
		require.NoError(rt, err)

		c1, err := key.EncryptWithNonce(p1, n1)
		require.NoError(rt, err)
		c2, err := key.EncryptWithNonce(p2, n2)
		require.NoError(rt, err)

		c, err := key.CiphertextOp(c1, c2)
		require.NoError(rt, err)

		p, err := key.PlaintextOp(p1, p2)
		require.NoError(rt, err)
		n, err := key.NonceOp(n1, n2)
		require.NoError(rt, err)

		cExpected, err := key.EncryptWithNonce(p, n)
		require.NoError(rt, err)

		require.True(rt, c.Equal(cExpected), "Ciphertext operation should correspond to the same operation on plaintexts and nonces")
	})
}

func (pr *HomomorphicEncryptionProperties[DK, EK, P, N, C, S]) DecryptingCiphertextHomOpMatchesPlaintextOp(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		encKey := decKey.Public()

		p1 := pr.PlaintextGenerator(t, encKey).Draw(rt, "plaintext 1")
		p2 := pr.PlaintextGenerator(t, encKey).Draw(rt, "plaintext 2")

		n1, err := encKey.SampleNonce(pr.PRNG())
		require.NoError(rt, err)
		n2, err := encKey.SampleNonce(pr.PRNG())
		require.NoError(rt, err)

		nCombined, err := encKey.NonceOp(n1, n2)
		require.NoError(rt, err)

		c1, err := encKey.EncryptWithNonce(p1, n1)
		require.NoError(rt, err)
		c2, err := encKey.EncryptWithNonce(p2, n2)
		require.NoError(rt, err)

		cCombined, err := encKey.CiphertextOp(c1, c2)
		require.NoError(rt, err)

		pCombinedExpected, err := encKey.PlaintextOp(p1, p2)
		require.NoError(rt, err)

		pCombinedDecrypted, err := decKey.Decrypt(cCombined)
		require.NoError(rt, err)

		require.True(rt, pr.PlaintextsAreEqual(pCombinedExpected, pCombinedDecrypted), "Decrypting the result of a ciphertext operation should yield the same result as applying the corresponding plaintext operation and then decrypting")

		cCombinedExpected, err := encKey.EncryptWithNonce(pCombinedExpected, nCombined)
		require.NoError(rt, err)

		require.True(rt, cCombined.Equal(cCombinedExpected), "The combined ciphertext should be equal to encrypting the combined plaintext with the combined nonce")
	})
}

func (pr *HomomorphicEncryptionProperties[DK, EK, P, N, C, S]) CiphertextScalarOpIsPlaintextNonceScalarOp(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decryptionKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decryptionKey)
		p := pr.PlaintextGenerator(t, key).Draw(rt, "plaintext")
		n, err := key.SampleNonce(pr.PRNG())
		require.NoError(rt, err)
		scalar := pr.ScalarGenerator(t, key).Draw(rt, "scalar")

		c, err := key.EncryptWithNonce(p, n)
		require.NoError(rt, err)

		cScalar, err := key.CiphertextScalarOp(c, scalar)
		require.NoError(rt, err)

		pScalarExpected, err := key.PlaintextScalarOp(p, scalar)
		require.NoError(rt, err)
		nScalarExpected, err := key.NonceScalarOp(n, scalar)
		require.NoError(rt, err)

		cExpected, err := key.EncryptWithNonce(pScalarExpected, nScalarExpected)
		require.NoError(rt, err)

		require.True(rt, cScalar.Equal(cExpected), "Ciphertext scalar operation should correspond to the same scalar operation on plaintext and nonce")
	})
}

func (pr *HomomorphicEncryptionProperties[DK, EK, P, N, C, S]) ReRandomiseShiftsNonce(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decryptionKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decryptionKey)
		plaintext := pr.PlaintextGenerator(t, key).Draw(rt, "plaintext")

		nonce, err := key.SampleNonce(pr.PRNG())
		require.NoError(rt, err)

		shift, err := key.SampleNonce(pr.PRNG())
		require.NoError(rt, err)

		ciphertext, err := key.EncryptWithNonce(plaintext, nonce)
		require.NoError(rt, err)

		rerandomised, err := key.ReRandomise(ciphertext, shift)
		require.NoError(rt, err)

		combinedNonce, err := key.NonceOp(nonce, shift)
		require.NoError(rt, err)

		expected, err := key.EncryptWithNonce(plaintext, combinedNonce)
		require.NoError(rt, err)

		require.True(rt, rerandomised.Equal(expected), "Re-randomising a ciphertext with a nonce shift should yield the same result as encrypting with the combined nonce")
	})
}

func (pr *HomomorphicEncryptionProperties[DK, EK, P, N, C, S]) CanShiftCiphertextByPlaintext(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decryptionKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decryptionKey)
		plaintext := pr.PlaintextGenerator(t, key).Draw(rt, "plaintext")
		delta := pr.PlaintextGenerator(t, key).Draw(rt, "delta")

		nonce, err := key.SampleNonce(pr.PRNG())
		require.NoError(rt, err)

		ciphertext, err := key.EncryptWithNonce(plaintext, nonce)
		require.NoError(rt, err)

		shifted, err := key.Shift(ciphertext, delta)
		require.NoError(rt, err)

		combinedPlaintext, err := key.PlaintextOp(plaintext, delta)
		require.NoError(rt, err)

		expected, err := key.EncryptWithNonce(combinedPlaintext, nonce)
		require.NoError(rt, err)

		require.True(rt, shifted.Equal(expected), "Shifting a ciphertext by a plaintext should yield the same result as encrypting the combined plaintext with the same nonce")
	})
}

func NewGroupHomomorphicEncryptionProperties[
	DK encryption.GroupHomomorphicDecryptionKey[EK, DK, P, PG, PV, N, NG, NV, C, CG, CV, S],
	EK encryption.GroupHomomorphicEncryptionKey[EK, P, PG, PV, N, NG, NV, C, CG, CV, S],
	P interface {
		encryption.Plaintext
		base.Transparent[PV]
	}, PG algebra.FiniteGroup[PV], PV algebra.GroupElement[PV],
	N interface {
		encryption.Nonce
		base.Transparent[NV]
	}, NG algebra.FiniteGroup[NV],
	NV algebra.GroupElement[NV],
	C interface {
		encryption.Ciphertext[C]
		base.Transparent[CV]
	}, CG algebra.FiniteGroup[CV], CV algebra.GroupElement[CV],
	S any,
](
	tb testing.TB,
	prng func() io.Reader,
	selfEncrypt bool,
	openable bool,
	decryptionKeyGenerator *rapid.Generator[DK],
	plaintextGenerator func(testing.TB, testutils.TypeErasedEncryptionKey[P, N, C]) *rapid.Generator[P],
	plaintextsAreEqual func(P, P) bool,
	noncesAreEqual func(N, N) bool,
	scalarGenerator func(testing.TB, testutils.TypeErasedHomomorphicEncryptionKey[P, N, C, S]) *rapid.Generator[S],
	ciphertextGenerator func(testing.TB, testutils.TypeErasedEncryptionKey[P, N, C]) *rapid.Generator[C],
	newPlaintext func(PV) (P, error),
	newNonce func(NV) (N, error),
	newCiphertext func(CV) (C, error),
	plaintextScalarOp func(testing.TB, P, S) P,
	nonceScalarOp func(testing.TB, N, S) N,
	ciphertextScalarOp func(testing.TB, C, S) C,
) *GroupHomomorphicEncryptionProperties[DK, EK, P, PG, PV, N, NG, NV, C, CG, CV, S] {
	tb.Helper()
	require.NotNil(tb, ciphertextGenerator, "ciphertextGenerator must not be nil")
	require.NotNil(tb, newPlaintext, "newPlaintext must not be nil")
	require.NotNil(tb, newNonce, "newNonce must not be nil")
	require.NotNil(tb, newCiphertext, "newCiphertext must not be nil")
	require.NotNil(tb, plaintextScalarOp, "plaintextScalarOp must not be nil")
	require.NotNil(tb, nonceScalarOp, "nonceScalarOp must not be nil")
	require.NotNil(tb, ciphertextScalarOp, "ciphertextScalarOp must not be nil")
	return &GroupHomomorphicEncryptionProperties[DK, EK, P, PG, PV, N, NG, NV, C, CG, CV, S]{
		HomomorphicEncryptionProperties: *NewHomomorphicEncryptionProperties(tb, prng, selfEncrypt, openable, decryptionKeyGenerator, plaintextGenerator, plaintextsAreEqual, noncesAreEqual, scalarGenerator),
		CiphertextGenerator:             ciphertextGenerator,
		NewPlaintext:                    newPlaintext,
		NewNonce:                        newNonce,
		NewCiphertext:                   newCiphertext,
		PlaintextScalarOp:               plaintextScalarOp,
		NonceScalarOp:                   nonceScalarOp,
		CiphertextScalarOp:              ciphertextScalarOp,
	}
}

type GroupHomomorphicEncryptionProperties[
	DK encryption.GroupHomomorphicDecryptionKey[EK, DK, P, PG, PV, N, NG, NV, C, CG, CV, S],
	EK encryption.GroupHomomorphicEncryptionKey[EK, P, PG, PV, N, NG, NV, C, CG, CV, S],
	P interface {
		encryption.Plaintext
		base.Transparent[PV]
	}, PG algebra.FiniteGroup[PV], PV algebra.GroupElement[PV],
	N interface {
		encryption.Nonce
		base.Transparent[NV]
	}, NG algebra.FiniteGroup[NV],
	NV algebra.GroupElement[NV],
	C interface {
		encryption.Ciphertext[C]
		base.Transparent[CV]
	}, CG algebra.FiniteGroup[CV], CV algebra.GroupElement[CV],
	S any,
] struct {
	HomomorphicEncryptionProperties[DK, EK, P, N, C, S]

	CiphertextGenerator func(testing.TB, testutils.TypeErasedEncryptionKey[P, N, C]) *rapid.Generator[C]

	NewPlaintext  func(PV) (P, error)
	NewNonce      func(NV) (N, error)
	NewCiphertext func(CV) (C, error)

	PlaintextScalarOp  func(testing.TB, P, S) P
	NonceScalarOp      func(testing.TB, N, S) N
	CiphertextScalarOp func(testing.TB, C, S) C
}

func (pr *GroupHomomorphicEncryptionProperties[DK, EK, P, PG, PV, N, NG, NV, C, CG, CV, S]) getEncryptionKey(tb testing.TB, dk DK) testutils.TypeErasedGroupHomomorphicEncryptionKey[P, PG, PV, N, NG, NV, C, CG, CV, S] {
	tb.Helper()
	var out testutils.TypeErasedGroupHomomorphicEncryptionKey[P, PG, PV, N, NG, NV, C, CG, CV, S]
	var ok bool
	if pr.SelfEncrypt {
		out, ok = any(dk).(encryption.GroupHomomorphicEncryptionKey[DK, P, PG, PV, N, NG, NV, C, CG, CV, S])
		require.True(tb, ok, "decryption key must also implement GroupHomomorphicEncryptionKey")
	} else {
		out = dk.Public()
	}
	return out
}

func (pr *GroupHomomorphicEncryptionProperties[DK, EK, P, PG, PV, N, NG, NV, C, CG, CV, S]) CheckAll(t *testing.T) {
	t.Parallel()
	t.Run("HomomorphicEncryptionProperties", pr.HomomorphicEncryptionProperties.CheckAll)
	t.Run("EncryptingPlaintextIdentityActsAsCiphertextSpaceIdentityUpToPlaintext", pr.EncryptingPlaintextIdentityActsAsCiphertextSpaceIdentityUpToPlaintext)
	t.Run("CiphertextInvIsPlaintextInvNonceInv", pr.CiphertextInvIsPlaintextInvNonceInv)
	t.Run("NonceOp", pr.NonceOp)
	t.Run("NonceOpInv", pr.NonceOpInv)
	t.Run("NonceScalarOpWorks", pr.NonceScalarOpWorks)
	t.Run("PlaintextOp", pr.PlaintextOp)
	t.Run("PlaintextOpInv", pr.PlaintextOpInv)
	t.Run("PlaintextScalarOpWorks", pr.PlaintextScalarOpWorks)
	t.Run("CiphertextOp", pr.CiphertextOp)
	t.Run("CiphertextOpInv", pr.CiphertextOpInv)
	t.Run("CiphertextScalarOpWorks", pr.CiphertextScalarOpWorks)
	t.Run("CiphertextScalarOpIsPlaintextNonceScalarOp", pr.CiphertextScalarOpIsPlaintextNonceScalarOp)
	t.Run("NonceGroupIsValid", pr.NonceGroupIsValid)
	t.Run("PlaintextGroupIsValid", pr.PlaintextGroupIsValid)
	t.Run("CiphertextGroupIsValid", pr.CiphertextGroupIsValid)
	t.Run("SampleNonceSamplesFromCorrectGroup", pr.SampleNonceSamplesFromCorrectGroup)
}

func (pr *GroupHomomorphicEncryptionProperties[DK, EK, P, PG, PV, N, NG, NV, C, CG, CV, S]) EncryptingPlaintextIdentityActsAsCiphertextSpaceIdentityUpToPlaintext(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decKey := pr.DecryptionKeyGenerator.Draw(rt, "encryption key")
		encKey := pr.getEncryptionKey(t, decKey)

		p := pr.PlaintextGenerator(t, encKey).Draw(rt, "plaintext")

		zero, err := pr.NewPlaintext(encKey.PlaintextGroup().OpIdentity())
		require.NoError(rt, err)

		nonce1, err := encKey.SampleNonce(pr.PRNG())
		require.NoError(rt, err)

		nonce2, err := encKey.SampleNonce(pr.PRNG())
		require.NoError(rt, err)

		c1, err := encKey.EncryptWithNonce(p, nonce1)
		require.NoError(rt, err)
		c2, err := encKey.EncryptWithNonce(zero, nonce2)
		require.NoError(rt, err)

		c, err := encKey.CiphertextOp(c1, c2)
		require.NoError(rt, err)

		actualPlaintext, err := decKey.Decrypt(c)
		require.NoError(rt, err)

		require.True(rt, pr.PlaintextsAreEqual(p, actualPlaintext), "Encrypting the plaintext identity and combining it with a ciphertext should yield a ciphertext that decrypts to the original plaintext")

	})
}

func (pr *GroupHomomorphicEncryptionProperties[DK, EK, P, PG, PV, N, NG, NV, C, CG, CV, S]) CiphertextInvIsPlaintextInvNonceInv(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decKey := pr.DecryptionKeyGenerator.Draw(rt, "encryption key")
		encKey := pr.getEncryptionKey(t, decKey)

		plaintext := pr.PlaintextGenerator(t, encKey).Draw(rt, "plaintext")
		nonce, err := encKey.SampleNonce(pr.PRNG())
		require.NoError(rt, err)

		plaintextInv, err := encKey.PlaintextOpInv(plaintext)
		require.NoError(rt, err)
		nonceInv, err := encKey.NonceOpInv(nonce)
		require.NoError(rt, err)

		ciphertext, err := encKey.EncryptWithNonce(plaintext, nonce)
		require.NoError(rt, err)

		expected, err := encKey.CiphertextOpInv(ciphertext)
		require.NoError(rt, err)

		actual, err := encKey.EncryptWithNonce(plaintextInv, nonceInv)
		require.NoError(rt, err)

		require.True(rt, expected.Equal(actual), "Ciphertext inverse should correspond to encrypting the inverses of the plaintext and nonce")
	})
}

func (pr *GroupHomomorphicEncryptionProperties[DK, EK, P, PG, PV, N, NG, NV, C, CG, CV, S]) NonceOp(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decKey)
		sampleCount := rapid.IntRange(2, 10).Draw(rt, "num samples")
		nonces := make([]N, sampleCount)
		var err error
		for i := range sampleCount {
			nonces[i], err = key.SampleNonce(pr.PRNG())
			require.NoError(t, err)
		}
		actual, err := key.NonceOp(nonces[0], nonces[1], nonces[2:]...)
		require.NoError(t, err)

		expectedValue := nonces[0].Value()
		for _, w := range nonces[1:] {
			expectedValue = expectedValue.Op(w.Value())
		}
		expected, err := pr.NewNonce(expectedValue)
		require.NoError(t, err)

		require.True(t, pr.NoncesAreEqual(expected, actual))
	})
}

func (pr *GroupHomomorphicEncryptionProperties[DK, EK, P, PG, PV, N, NG, NV, C, CG, CV, S]) NonceOpInv(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decKey)
		nonce, err := key.SampleNonce(pr.PRNG())
		require.NoError(t, err)

		actual, err := key.NonceOpInv(nonce)
		require.NoError(t, err)

		expectedValue := nonce.Value().OpInv()
		expected, err := pr.NewNonce(expectedValue)
		require.NoError(t, err)

		require.True(t, pr.NoncesAreEqual(expected, actual))
	})
}

func (pr *GroupHomomorphicEncryptionProperties[DK, EK, P, PG, PV, N, NG, NV, C, CG, CV, S]) NonceScalarOpWorks(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decKey)
		nonce, err := key.SampleNonce(pr.PRNG())
		require.NoError(t, err)

		scalar := pr.ScalarGenerator(t, key).Draw(rt, "scalar")

		actual, err := key.NonceScalarOp(nonce, scalar)
		require.NoError(t, err)

		expected := pr.NonceScalarOp(t, nonce, scalar)

		require.True(t, pr.NoncesAreEqual(expected, actual))
	})
}

func (pr *GroupHomomorphicEncryptionProperties[DK, EK, P, PG, PV, N, NG, NV, C, CG, CV, S]) PlaintextOp(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decKey)
		messages := rapid.SliceOfN(pr.PlaintextGenerator(t, key), 2, 10).Draw(rt, "messages")
		actual, err := key.PlaintextOp(messages[0], messages[1], messages[2:]...)
		require.NoError(t, err)

		expectedValue := messages[0].Value()
		for _, w := range messages[1:] {
			expectedValue = expectedValue.Op(w.Value())
		}
		expected, err := pr.NewPlaintext(expectedValue)
		require.NoError(t, err)

		require.True(t, pr.PlaintextsAreEqual(expected, actual))
	})
}

func (pr *GroupHomomorphicEncryptionProperties[DK, EK, P, PG, PV, N, NG, NV, C, CG, CV, S]) PlaintextOpInv(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decKey)
		plaintext := pr.PlaintextGenerator(t, key).Draw(rt, "plaintext")

		actual, err := key.PlaintextOpInv(plaintext)
		require.NoError(t, err)

		expectedValue := plaintext.Value().OpInv()
		expected, err := pr.NewPlaintext(expectedValue)
		require.NoError(t, err)

		require.True(t, pr.PlaintextsAreEqual(expected, actual))
	})
}

func (pr *GroupHomomorphicEncryptionProperties[DK, EK, P, PG, PV, N, NG, NV, C, CG, CV, S]) PlaintextScalarOpWorks(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decKey)
		plaintext := pr.PlaintextGenerator(t, key).Draw(rt, "plaintext")
		scalar := pr.ScalarGenerator(t, key).Draw(rt, "scalar")

		actual, err := key.PlaintextScalarOp(plaintext, scalar)
		require.NoError(t, err)

		expected := pr.PlaintextScalarOp(t, plaintext, scalar)

		require.True(t, pr.PlaintextsAreEqual(expected, actual))
	})
}

func (pr *GroupHomomorphicEncryptionProperties[DK, EK, P, PG, PV, N, NG, NV, C, CG, CV, S]) CiphertextOp(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decKey)
		ciphertexts := rapid.SliceOfN(pr.CiphertextGenerator(t, key), 2, 10).Draw(rt, "ciphertexts")
		actual, err := key.CiphertextOp(ciphertexts[0], ciphertexts[1], ciphertexts[2:]...)
		require.NoError(t, err)

		expectedValue := ciphertexts[0].Value()
		for _, w := range ciphertexts[1:] {
			expectedValue = expectedValue.Op(w.Value())
		}
		expected, err := pr.NewCiphertext(expectedValue)
		require.NoError(t, err)

		require.True(t, expected.Equal(actual))
	})
}

func (pr *GroupHomomorphicEncryptionProperties[DK, EK, P, PG, PV, N, NG, NV, C, CG, CV, S]) CiphertextOpInv(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decKey)
		ciphertext := pr.CiphertextGenerator(t, key).Draw(rt, "ciphertext")

		actual, err := key.CiphertextOpInv(ciphertext)
		require.NoError(t, err)

		expectedValue := ciphertext.Value().OpInv()
		expected, err := pr.NewCiphertext(expectedValue)
		require.NoError(t, err)

		require.True(t, expected.Equal(actual))
	})
}

func (pr *GroupHomomorphicEncryptionProperties[DK, EK, P, PG, PV, N, NG, NV, C, CG, CV, S]) CiphertextScalarOpWorks(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decKey)
		ciphertext := pr.CiphertextGenerator(t, key).Draw(rt, "ciphertext")
		scalar := pr.ScalarGenerator(t, key).Draw(rt, "scalar")

		actual, err := key.CiphertextScalarOp(ciphertext, scalar)
		require.NoError(t, err)

		expected := pr.CiphertextScalarOp(t, ciphertext, scalar)

		require.True(t, expected.Equal(actual))
	})
}

func (pr *GroupHomomorphicEncryptionProperties[DK, EK, P, PG, PV, N, NG, NV, C, CG, CV, S]) CiphertextScalarOpIsPlaintextNonceScalarOp(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decKey)
		message := pr.PlaintextGenerator(t, key).Draw(rt, "message")
		scalar := pr.ScalarGenerator(t, key).Draw(rt, "scalar")

		nonce, err := key.SampleNonce(pr.PRNG())
		require.NoError(t, err)

		ciphertext, err := key.EncryptWithNonce(message, nonce)
		require.NoError(t, err)

		messageScalar, err := key.PlaintextScalarOp(message, scalar)
		require.NoError(t, err)

		nonceScalar, err := key.NonceScalarOp(nonce, scalar)
		require.NoError(t, err)

		ciphertextScalarExpected, err := key.EncryptWithNonce(messageScalar, nonceScalar)
		require.NoError(t, err)

		ciphertextScalarActual, err := key.CiphertextScalarOp(ciphertext, scalar)
		require.NoError(t, err)

		require.True(t, ciphertextScalarExpected.Equal(ciphertextScalarActual))
	})
}

func (pr *GroupHomomorphicEncryptionProperties[DK, EK, P, PG, PV, N, NG, NV, C, CG, CV, S]) NonceGroupIsValid(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decKey)
		nonceGroup := key.NonceGroup()
		nonceValue, err := nonceGroup.Random(pr.PRNG())
		require.NoError(rt, err)
		nonce, err := pr.NewNonce(nonceValue)
		require.NoError(rt, err)
		require.True(rt, nonce.Value().Equal(nonceValue))
	})
}

func (pr *GroupHomomorphicEncryptionProperties[DK, EK, P, PG, PV, N, NG, NV, C, CG, CV, S]) PlaintextGroupIsValid(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decKey)
		plaintextGroup := key.PlaintextGroup()
		plaintextValue, err := plaintextGroup.Random(pr.PRNG())
		require.NoError(rt, err)
		plaintext, err := pr.NewPlaintext(plaintextValue)
		require.NoError(rt, err)
		require.True(rt, plaintext.Value().Equal(plaintextValue))
	})
}

func (pr *GroupHomomorphicEncryptionProperties[DK, EK, P, PG, PV, N, NG, NV, C, CG, CV, S]) CiphertextGroupIsValid(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decKey)
		ciphertextGroup := key.CiphertextGroup()
		ciphertextValue, err := ciphertextGroup.Random(pr.PRNG())
		require.NoError(rt, err)
		ciphertext, err := pr.NewCiphertext(ciphertextValue)
		require.NoError(rt, err)
		require.True(rt, ciphertext.Value().Equal(ciphertextValue))
	})
}

func (pr *GroupHomomorphicEncryptionProperties[DK, EK, P, PG, PV, N, NG, NV, C, CG, CV, S]) SampleNonceSamplesFromCorrectGroup(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		decKey := pr.DecryptionKeyGenerator.Draw(rt, "decryption key")
		key := pr.getEncryptionKey(t, decKey)
		nonce, err := key.SampleNonce(pr.PRNG())
		require.NoError(rt, err)
		require.True(rt, key.NonceGroup().Contains(nonce.Value()))
	})
}
