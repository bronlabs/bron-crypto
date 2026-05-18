package indcpacom_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/prng"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/indcpacom"
	"github.com/bronlabs/bron-crypto/pkg/commitments/testutils/properties"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

type (
	paillierCommitmentKey[EK interface {
		*paillier.PublicKey | *paillier.SecretKey
		encryption.HomomorphicEncryptionKey[EK, *paillier.Plaintext, *paillier.Nonce, *paillier.Ciphertext, *num.Int]
	}] = indcpacom.HomomorphicCommitmentKey[
		EK,
		*paillier.Plaintext,
		*paillier.Nonce,
		*paillier.Ciphertext,
		*num.Int,
	]

	paillierCommitment = indcpacom.Commitment[*paillier.Ciphertext]
	paillierWitness    = indcpacom.Witness[*paillier.Nonce]
	paillierMessage    = indcpacom.Message[*paillier.Plaintext]
)

func PaillierCommitmentKeyGenerator(tb testing.TB, keyLen int) *rapid.Generator[*paillierCommitmentKey[*paillier.PublicKey]] {
	tb.Helper()
	return rapid.Custom(func(rt *rapid.T) *paillierCommitmentKey[*paillier.PublicKey] {
		seed := rapid.Uint64().Draw(rt, "seed")
		salt := rapid.Uint64().Draw(rt, "salt")
		prng := pcg.New(seed, salt)
		enc, err := paillier.SampleSecretKey(uint(keyLen), prng)
		require.NoError(rt, err)
		key, err := indcpacom.NewHomomorphicCommitmentKey(enc.Public())
		require.NoError(rt, err)
		return key
	})
}

func PaillierCommitmentKeyGenerator_SelfEncrypt(tb testing.TB, keyLen int) *rapid.Generator[*paillierCommitmentKey[*paillier.SecretKey]] {
	tb.Helper()
	return rapid.Custom(func(rt *rapid.T) *paillierCommitmentKey[*paillier.SecretKey] {
		seed := rapid.Uint64().Draw(rt, "seed")
		salt := rapid.Uint64().Draw(rt, "salt")
		prng := pcg.New(seed, salt)
		enc, err := paillier.SampleSecretKey(uint(keyLen), prng)
		require.NoError(rt, err)
		key, err := indcpacom.NewHomomorphicCommitmentKey(enc)
		require.NoError(rt, err)
		return key
	})
}

func PaillierCommitmentGenerator[
	EK interface {
		*paillier.PublicKey | *paillier.SecretKey
	}, K commitments.CommitmentKey[K, *paillierMessage, *paillierWitness, *paillierCommitment],
](
	tb testing.TB, key commitments.CommitmentKey[K, *paillierMessage, *paillierWitness, *paillierCommitment],
) *rapid.Generator[*paillierCommitment] {
	tb.Helper()
	encKeyWrapper, ok := key.(interface {
		EncryptionKey() EK
	})
	require.True(tb, ok, "commitment key does not have a paillier encryption key")
	obj, ok := any(encKeyWrapper.EncryptionKey()).(interface {
		CiphertextGroup() *znstar.PaillierGroupUnknownOrder
	})
	require.True(tb, ok, "encryption key does not have a ciphertext group")
	ctGroup := obj.CiphertextGroup()
	return rapid.Custom(func(rt *rapid.T) *paillierCommitment {
		seed := rapid.Uint64().Draw(rt, "seed")
		salt := rapid.Uint64().Draw(rt, "salt")
		prng := pcg.New(seed, salt)
		v, err := ctGroup.Random(prng)
		require.NoError(rt, err)
		ciphertext, err := paillier.NewCiphertextFromGroupElement(v)
		require.NoError(rt, err)
		commitment, err := indcpacom.NewCommitment(ciphertext)
		require.NoError(rt, err)
		return commitment
	})
}

func PaillierWitnessGenerator[
	EK interface {
		*paillier.PublicKey | *paillier.SecretKey
	}, K commitments.CommitmentKey[K, *paillierMessage, *paillierWitness, *paillierCommitment],
](
	tb testing.TB, key commitments.CommitmentKey[K, *paillierMessage, *paillierWitness, *paillierCommitment],
) *rapid.Generator[*paillierWitness] {
	tb.Helper()
	encKeyWrapper, ok := key.(interface {
		EncryptionKey() EK
	})
	require.True(tb, ok, "commitment key does not have a paillier encryption key")
	obj, ok := any(encKeyWrapper.EncryptionKey()).(interface {
		NonceGroup() *znstar.RSAGroupUnknownOrder
	})
	require.True(tb, ok, "encryption key does not have a nonce group")
	nonceGroup := obj.NonceGroup()
	return rapid.Custom(func(rt *rapid.T) *paillierWitness {
		seed := rapid.Uint64().Draw(rt, "seed")
		salt := rapid.Uint64().Draw(rt, "salt")
		prng := pcg.New(seed, salt)
		v, err := nonceGroup.Random(prng)
		require.NoError(rt, err)
		nonce, err := paillier.NewNonceFromGroupElement(v)
		require.NoError(rt, err)
		witness, err := indcpacom.NewWitness(nonce)
		require.NoError(rt, err)
		return witness
	})
}

func PaillierMessageGenerator[
	EK interface {
		*paillier.PublicKey | *paillier.SecretKey
	}, K commitments.CommitmentKey[K, *paillierMessage, *paillierWitness, *paillierCommitment],
](
	tb testing.TB, key commitments.CommitmentKey[K, *paillierMessage, *paillierWitness, *paillierCommitment],
) *rapid.Generator[*paillierMessage] {
	tb.Helper()
	encKeyWrapper, ok := key.(interface {
		EncryptionKey() EK
	})
	require.True(tb, ok, "commitment key does not have a paillier encryption key")
	obj, ok := any(encKeyWrapper.EncryptionKey()).(interface {
		PlaintextGroup() *num.ZMod
	})
	require.True(tb, ok, "encryption key does not have a plaintext group")
	plaintextGroup := obj.PlaintextGroup()
	return rapid.Custom(func(rt *rapid.T) *paillierMessage {
		seed := rapid.Uint64().Draw(rt, "seed")
		salt := rapid.Uint64().Draw(rt, "salt")
		prng := pcg.New(seed, salt)
		v, err := plaintextGroup.Random(prng)
		require.NoError(rt, err)
		plaintext, err := paillier.NewPlaintext(v)
		require.NoError(rt, err)
		message, err := indcpacom.NewMessage(plaintext)
		require.NoError(rt, err)
		return message
	})
}

func PaillierScalarGenerator[
	EK interface {
		*paillier.PublicKey | *paillier.SecretKey
	}, K commitments.HomomorphicCommitmentKey[K, *paillierMessage, *paillierWitness, *paillierCommitment, *num.Int],
](
	tb testing.TB, key commitments.HomomorphicCommitmentKey[K, *paillierMessage, *paillierWitness, *paillierCommitment, *num.Int],
) *rapid.Generator[*num.Int] {
	tb.Helper()
	encKeyWrapper, ok := key.(interface {
		EncryptionKey() EK
	})
	require.True(tb, ok, "commitment key does not have a paillier encryption key")
	obj, ok := any(encKeyWrapper.EncryptionKey()).(interface {
		CiphertextGroup() *znstar.PaillierGroupUnknownOrder
	})
	require.True(tb, ok, "encryption key does not have a ciphertext group")
	ctGroup := obj.CiphertextGroup()
	return rapid.Custom(func(rt *rapid.T) *num.Int {
		seed := rapid.Uint64().Draw(rt, "seed")
		salt := rapid.Uint64().Draw(rt, "salt")
		prng := pcg.New(seed, salt)
		modulus := ctGroup.Modulus()
		s, err := num.Z().Random(modulus.Lift().Neg(), modulus.Lift(), prng)
		require.NoError(rt, err)
		return s
	})
}

type PaillierHomomorphicCommitmentKeyProperties = properties.HomomorphicCommitmentKeyProperties[
	*paillierCommitmentKey[*paillier.PublicKey],
	*paillierMessage,
	*paillierWitness,
	*paillierCommitment,
	*num.Int,
]

type PaillierHomomorphicCommitmentKeyProperties_SelfEncrypt = properties.HomomorphicCommitmentKeyProperties[
	*paillierCommitmentKey[*paillier.SecretKey],
	*paillierMessage,
	*paillierWitness,
	*paillierCommitment,
	*num.Int,
]

func PaillierCommitmentKeyPropertySuite(tb testing.TB, keyLen int) *PaillierHomomorphicCommitmentKeyProperties {
	tb.Helper()
	return properties.NewHomomorphicCommitmentKeyProperties(
		tb,
		prng.PRNGFuncTypeErase(pcg.NewRandomised),
		PaillierCommitmentKeyGenerator(tb, keyLen),
		PaillierMessageGenerator[*paillier.PublicKey],
		func(m1, m2 *paillierMessage) bool { return m1.Value().Equal(m2.Value()) },
		func(w1, w2 *paillierWitness) bool { return w1.Value().Equal(w2.Value()) },
		PaillierScalarGenerator[*paillier.PublicKey],
	)
}

func PaillierCommitmentKeyPropertySuite_SelfEncrypt(tb testing.TB, keyLen int) *PaillierHomomorphicCommitmentKeyProperties_SelfEncrypt {
	tb.Helper()
	return properties.NewHomomorphicCommitmentKeyProperties(
		tb,
		prng.PRNGFuncTypeErase(pcg.NewRandomised),
		PaillierCommitmentKeyGenerator_SelfEncrypt(tb, keyLen),
		PaillierMessageGenerator[*paillier.SecretKey],
		func(m1, m2 *paillierMessage) bool { return m1.Value().Equal(m2.Value()) },
		func(w1, w2 *paillierWitness) bool { return w1.Value().Equal(w2.Value()) },
		PaillierScalarGenerator[*paillier.SecretKey],
	)
}

func PaillierWitnessPropertySuite(tb testing.TB, keyLen int) *properties.WitnessProperties[*paillierWitness] {
	tb.Helper()
	enc, err := paillier.SampleSecretKey(uint(keyLen), pcg.NewRandomised())
	require.NoError(tb, err)
	key, err := indcpacom.NewHomomorphicCommitmentKey(enc.Public())
	require.NoError(tb, err)
	return &properties.WitnessProperties[*paillierWitness]{
		WitnessGenerator: PaillierWitnessGenerator[*paillier.PublicKey](tb, key),
		WitnessesAreEqual: func(w1, w2 *paillierWitness) bool {
			if w1 == nil || w2 == nil {
				return w1 == w2
			}
			return w1.Value().Equal(w2.Value())
		},
	}
}

func PaillierMessagePropertySuite(tb testing.TB, keyLen int) *properties.MessageProperties[*paillierMessage] {
	tb.Helper()
	enc, err := paillier.SampleSecretKey(uint(keyLen), pcg.NewRandomised())
	require.NoError(tb, err)
	key, err := indcpacom.NewHomomorphicCommitmentKey(enc.Public())
	require.NoError(tb, err)
	return &properties.MessageProperties[*paillierMessage]{
		MessageGenerator: PaillierMessageGenerator[*paillier.PublicKey](tb, key),
		MessagesAreEqual: func(m1, m2 *paillierMessage) bool {
			if m1 == nil || m2 == nil {
				return m1 == m2
			}
			return m1.Value().Equal(m2.Value())
		},
	}
}

func PaillierCommitmentPropertySuite(tb testing.TB, keyLen int) *properties.CommitmentProperties[*paillierCommitment] {
	tb.Helper()
	enc, err := paillier.SampleSecretKey(uint(keyLen), pcg.NewRandomised())
	require.NoError(tb, err)
	key, err := indcpacom.NewHomomorphicCommitmentKey(enc.Public())
	require.NoError(tb, err)
	return &properties.CommitmentProperties[*paillierCommitment]{
		CommitmentGenerator: PaillierCommitmentGenerator[*paillier.PublicKey](tb, key),
		CommitmentsAreEqual: func(c1, c2 *paillierCommitment) bool { return c1.Equal(c2) },
	}
}

func TestPaillierCommitmentKeyProperties(t *testing.T) {
	t.Parallel()
	t.Run("64-bit key", PaillierCommitmentKeyPropertySuite(t, 64).CheckAll)
}

func TestPaillierCommitmentKeyProperties_SelfEncrypt(t *testing.T) {
	t.Parallel()
	t.Run("64-bit key", PaillierCommitmentKeyPropertySuite_SelfEncrypt(t, 64).CheckAll)
}

func TestPaillierWitnessProperties(t *testing.T) {
	t.Parallel()
	t.Run("1024-bit key", PaillierWitnessPropertySuite(t, 1024).CheckAll)
}

func TestPaillierMessageProperties(t *testing.T) {
	t.Parallel()
	t.Run("1024-bit key", PaillierMessagePropertySuite(t, 1024).CheckAll)
}

func TestPaillierCommitmentProperties(t *testing.T) {
	t.Parallel()
	t.Run("1024-bit key", PaillierCommitmentPropertySuite(t, 1024).CheckAll)
}
