package indcpacom_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/indcpacom"
	"github.com/bronlabs/bron-crypto/pkg/commitments/testutils/properties"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

type (
	elgamalCommitmentKey[
		EK interface {
			*elgamal.PublicKey[E, S] | *elgamal.SecretKey[E, S]
			encryption.HomomorphicEncryptionKey[EK, *elgamal.Plaintext[E, S], *elgamal.Nonce[S], *elgamal.Ciphertext[E, S], S]
		}, E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S],
	] = indcpacom.HomomorphicCommitmentKey[
		EK,
		*elgamal.Plaintext[E, S],
		*elgamal.Nonce[S],
		*elgamal.Ciphertext[E, S],
		S,
	]
	elgamalCommitment[E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]] = indcpacom.Commitment[*elgamal.Ciphertext[E, S]]
	elgamalWitness[S algebra.UintLike[S]]                                              = indcpacom.Witness[*elgamal.Nonce[S]]
	elgamalMessage[E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]]    = indcpacom.Message[*elgamal.Plaintext[E, S]]
)

func ElGamalCommitmentKeyGenerator[
	E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S],
](tb testing.TB, group elgamal.FiniteCyclicGroup[E, S]) *rapid.Generator[*elgamalCommitmentKey[*elgamal.PublicKey[E, S], E, S]] {
	tb.Helper()
	return rapid.Custom(func(rt *rapid.T) *elgamalCommitmentKey[*elgamal.PublicKey[E, S], E, S] {
		seed := rapid.Uint64().Draw(rt, "seed")
		salt := rapid.Uint64().Draw(rt, "salt")
		prng := pcg.New(seed, salt)
		enc, err := elgamal.SampleSecretKey(group, prng)
		require.NoError(rt, err)
		key, err := indcpacom.NewHomomorphicCommitmentKey(enc.Public())
		require.NoError(rt, err)
		return key
	})
}

func ElGamalCommitmentKeyGenerator_SelfEncrypt[
	E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S],
](tb testing.TB, group elgamal.FiniteCyclicGroup[E, S]) *rapid.Generator[*elgamalCommitmentKey[*elgamal.SecretKey[E, S], E, S]] {
	tb.Helper()
	return rapid.Custom(func(rt *rapid.T) *elgamalCommitmentKey[*elgamal.SecretKey[E, S], E, S] {
		seed := rapid.Uint64().Draw(rt, "seed")
		salt := rapid.Uint64().Draw(rt, "salt")
		prng := pcg.New(seed, salt)
		enc, err := elgamal.SampleSecretKey(group, prng)
		require.NoError(rt, err)
		key, err := indcpacom.NewHomomorphicCommitmentKey(enc)
		require.NoError(rt, err)
		return key
	})
}

func ElGamalCommitmentGenerator[
	EK interface {
		*elgamal.PublicKey[E, S] | *elgamal.SecretKey[E, S]
	}, E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S],
	K commitments.CommitmentKey[K, *elgamalMessage[E, S], *elgamalWitness[S], *elgamalCommitment[E, S]],
](
	tb testing.TB, key commitments.CommitmentKey[K, *elgamalMessage[E, S], *elgamalWitness[S], *elgamalCommitment[E, S]],
) *rapid.Generator[*elgamalCommitment[E, S]] {
	tb.Helper()
	encKeyWrapper, ok := key.(interface {
		EncryptionKey() EK
	})
	require.True(tb, ok, "commitment key must have an encryption key of the correct type")
	obj, ok := any(encKeyWrapper.EncryptionKey()).(interface {
		CiphertextGroup() *constructions.FiniteDirectPowerModule[elgamal.FiniteCyclicGroup[E, S], E, S]
	})
	require.True(tb, ok, "encryption key must have a ciphertext group of the correct type")
	ctGroup := obj.CiphertextGroup()
	return rapid.Custom(func(rt *rapid.T) *elgamalCommitment[E, S] {
		seed := rapid.Uint64().Draw(rt, "seed")
		salt := rapid.Uint64().Draw(rt, "salt")
		prng := pcg.New(seed, salt)
		v, err := ctGroup.Random(prng)
		require.NoError(rt, err)
		ciphertext, err := elgamal.NewCiphertextFromGroupElement(v)
		require.NoError(rt, err)
		commitment, err := indcpacom.NewCommitment(ciphertext)
		require.NoError(rt, err)
		return commitment
	})
}

func ElGamalWitnessGenerator[
	EK interface {
		*elgamal.PublicKey[E, S] | *elgamal.SecretKey[E, S]
	}, E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S],
	K commitments.CommitmentKey[K, *elgamalMessage[E, S], *elgamalWitness[S], *elgamalCommitment[E, S]],
](
	tb testing.TB, key commitments.CommitmentKey[K, *elgamalMessage[E, S], *elgamalWitness[S], *elgamalCommitment[E, S]],
) *rapid.Generator[*elgamalWitness[S]] {
	tb.Helper()
	encKeyWrapper, ok := key.(interface {
		EncryptionKey() EK
	})
	require.True(tb, ok, "commitment key must have an encryption key of the correct type")
	obj, ok := any(encKeyWrapper.EncryptionKey()).(interface {
		NonceGroup() algebra.ZModLike[S]
	})
	require.True(tb, ok, "encryption key must have a nonce group of the correct type")
	nonceGroup := obj.NonceGroup()
	return rapid.Custom(func(rt *rapid.T) *elgamalWitness[S] {
		seed := rapid.Uint64().Draw(rt, "seed")
		salt := rapid.Uint64().Draw(rt, "salt")
		prng := pcg.New(seed, salt)
		v, err := nonceGroup.Random(prng)
		require.NoError(rt, err)
		nonce, err := elgamal.NewNonce(v)
		require.NoError(rt, err)
		witness, err := indcpacom.NewWitness(nonce)
		require.NoError(rt, err)
		return witness
	})
}

func ElGamalMessageGenerator[
	EK interface {
		*elgamal.PublicKey[E, S] | *elgamal.SecretKey[E, S]
	}, E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S],
	K commitments.CommitmentKey[K, *elgamalMessage[E, S], *elgamalWitness[S], *elgamalCommitment[E, S]],
](
	tb testing.TB, key commitments.CommitmentKey[K, *elgamalMessage[E, S], *elgamalWitness[S], *elgamalCommitment[E, S]],
) *rapid.Generator[*elgamalMessage[E, S]] {
	tb.Helper()
	encKeyWrapper, ok := key.(interface {
		EncryptionKey() EK
	})
	require.True(tb, ok, "commitment key must have an encryption key of the correct type")
	obj, ok := any(encKeyWrapper.EncryptionKey()).(interface {
		PlaintextGroup() elgamal.FiniteCyclicGroup[E, S]
	})
	require.True(tb, ok, "encryption key must have a plaintext group of the correct type")
	ptGroup := obj.PlaintextGroup()
	return rapid.Custom(func(rt *rapid.T) *elgamalMessage[E, S] {
		seed := rapid.Uint64().Draw(rt, "seed")
		salt := rapid.Uint64().Draw(rt, "salt")
		prng := pcg.New(seed, salt)
		v, err := ptGroup.Random(prng)
		require.NoError(rt, err)
		plaintext, err := elgamal.NewPlaintext(v)
		require.NoError(rt, err)
		message, err := indcpacom.NewMessage(plaintext)
		require.NoError(rt, err)
		return message
	})
}

func ElGamalScalarGenerator[
	EK interface {
		*elgamal.PublicKey[E, S] | *elgamal.SecretKey[E, S]
	}, E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S],
	K commitments.HomomorphicCommitmentKey[K, *elgamalMessage[E, S], *elgamalWitness[S], *elgamalCommitment[E, S], S],
](
	tb testing.TB, key commitments.HomomorphicCommitmentKey[K, *elgamalMessage[E, S], *elgamalWitness[S], *elgamalCommitment[E, S], S],
) *rapid.Generator[S] {
	tb.Helper()
	encKeyWrapper, ok := key.(interface {
		EncryptionKey() EK
	})
	require.True(tb, ok, "commitment key must have an encryption key of the correct type")
	obj, ok := any(encKeyWrapper.EncryptionKey()).(interface {
		NonceGroup() algebra.ZModLike[S]
	})
	require.True(tb, ok, "encryption key must have a nonce group of the correct type")
	nonceGroup := obj.NonceGroup()
	return rapid.Custom(func(rt *rapid.T) S {
		seed := rapid.Uint64().Draw(rt, "seed")
		salt := rapid.Uint64().Draw(rt, "salt")
		prng := pcg.New(seed, salt)
		v, err := nonceGroup.Random(prng)
		require.NoError(rt, err)
		return v
	})
}

type ElGamalHomomorphicCommitmentKeyProperties[
	E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S],
] = properties.HomomorphicCommitmentKeyProperties[
	*elgamalCommitmentKey[*elgamal.PublicKey[E, S], E, S],
	*elgamalMessage[E, S],
	*elgamalWitness[S],
	*elgamalCommitment[E, S],
	S,
]

type ElGamalHomomorphicCommitmentKeyProperties_SelfEncrypt[
	E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S],
] = properties.HomomorphicCommitmentKeyProperties[
	*elgamalCommitmentKey[*elgamal.SecretKey[E, S], E, S],
	*elgamalMessage[E, S],
	*elgamalWitness[S],
	*elgamalCommitment[E, S],
	S,
]

func ElGamalCommitmentKeyPropertySuite[
	E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S],
](
	tb testing.TB, group elgamal.FiniteCyclicGroup[E, S],
) *ElGamalHomomorphicCommitmentKeyProperties[E, S] {
	tb.Helper()
	return properties.NewHomomorphicCommitmentKeyProperties(
		tb,
		prng.PRNGFuncTypeErase(pcg.NewRandomised),
		ElGamalCommitmentKeyGenerator(tb, group),
		ElGamalMessageGenerator[*elgamal.PublicKey[E, S]],
		func(m1, m2 *elgamalMessage[E, S]) bool { return m1.Value().Equal(m2.Value()) },
		func(w1, w2 *elgamalWitness[S]) bool { return w1.Value().Equal(w2.Value()) },
		ElGamalScalarGenerator[*elgamal.PublicKey[E, S]],
	)
}

func ElGamalCommitmentKeyPropertySuite_SelfEncrypt[
	E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S],
](
	tb testing.TB, group elgamal.FiniteCyclicGroup[E, S],
) *ElGamalHomomorphicCommitmentKeyProperties_SelfEncrypt[E, S] {
	tb.Helper()
	return properties.NewHomomorphicCommitmentKeyProperties(
		tb,
		prng.PRNGFuncTypeErase(pcg.NewRandomised),
		ElGamalCommitmentKeyGenerator_SelfEncrypt(tb, group),
		ElGamalMessageGenerator[*elgamal.SecretKey[E, S]],
		func(m1, m2 *elgamalMessage[E, S]) bool { return m1.Value().Equal(m2.Value()) },
		func(w1, w2 *elgamalWitness[S]) bool { return w1.Value().Equal(w2.Value()) },
		ElGamalScalarGenerator[*elgamal.SecretKey[E, S]],
	)
}

func ElGamalWitnessPropertySuite[
	E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S],
](
	tb testing.TB, group elgamal.FiniteCyclicGroup[E, S],
) *properties.WitnessProperties[*elgamalWitness[S]] {
	tb.Helper()
	enc, err := elgamal.SampleSecretKey(group, pcg.NewRandomised())
	require.NoError(tb, err)
	key, err := indcpacom.NewHomomorphicCommitmentKey(enc.Public())
	require.NoError(tb, err)
	return &properties.WitnessProperties[*elgamalWitness[S]]{
		WitnessGenerator: ElGamalWitnessGenerator[*elgamal.PublicKey[E, S]](tb, key),
		WitnessesAreEqual: func(w1, w2 *elgamalWitness[S]) bool {
			if w1 == nil || w2 == nil {
				return w1 == w2
			}
			return w1.Value().Equal(w2.Value())
		},
	}
}

func ElGamalMessagePropertySuite[
	E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S],
](
	tb testing.TB, group elgamal.FiniteCyclicGroup[E, S],
) *properties.MessageProperties[*elgamalMessage[E, S]] {
	tb.Helper()
	enc, err := elgamal.SampleSecretKey(group, pcg.NewRandomised())
	require.NoError(tb, err)
	key, err := indcpacom.NewHomomorphicCommitmentKey(enc.Public())
	require.NoError(tb, err)
	return &properties.MessageProperties[*elgamalMessage[E, S]]{
		MessageGenerator: ElGamalMessageGenerator[*elgamal.PublicKey[E, S]](tb, key),
		MessagesAreEqual: func(m1, m2 *elgamalMessage[E, S]) bool {
			if m1 == nil || m2 == nil {
				return m1 == m2
			}
			return m1.Value().Equal(m2.Value())
		},
	}
}

func ElGamalCommitmentGeneratorPropertySuite[
	E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S],
](
	tb testing.TB, group elgamal.FiniteCyclicGroup[E, S],
) *properties.CommitmentProperties[*elgamalCommitment[E, S]] {
	tb.Helper()
	enc, err := elgamal.SampleSecretKey(group, pcg.NewRandomised())
	require.NoError(tb, err)
	key, err := indcpacom.NewHomomorphicCommitmentKey(enc.Public())
	require.NoError(tb, err)
	return &properties.CommitmentProperties[*elgamalCommitment[E, S]]{
		CommitmentGenerator: ElGamalCommitmentGenerator[*elgamal.PublicKey[E, S]](tb, key),
		CommitmentsAreEqual: func(c1, c2 *elgamalCommitment[E, S]) bool { return c1.Equal(c2) },
	}
}

func TestElGamalCommitmentKeyProperties(t *testing.T) {
	t.Parallel()
	t.Run("k256 group", ElGamalCommitmentKeyPropertySuite(t, k256.NewCurve()).CheckAll)
	t.Run("edwards25519 group", ElGamalCommitmentKeyPropertySuite(t, edwards25519.NewPrimeSubGroup()).CheckAll)
}

func TestElGamalCommitmentKeyProperties_SelfEncrypt(t *testing.T) {
	t.Parallel()
	t.Run("k256 group", ElGamalCommitmentKeyPropertySuite_SelfEncrypt(t, k256.NewCurve()).CheckAll)
	t.Run("edwards25519 group", ElGamalCommitmentKeyPropertySuite_SelfEncrypt(t, edwards25519.NewPrimeSubGroup()).CheckAll)
}

func TestElGamalWitnessProperties(t *testing.T) {
	t.Parallel()
	t.Run("k256 group", ElGamalWitnessPropertySuite(t, k256.NewCurve()).CheckAll)
	t.Run("edwards25519 group", ElGamalWitnessPropertySuite(t, edwards25519.NewPrimeSubGroup()).CheckAll)
}

func TestElGamalMessageProperties(t *testing.T) {
	t.Parallel()
	t.Run("k256 group", ElGamalMessagePropertySuite(t, k256.NewCurve()).CheckAll)
	t.Run("edwards25519 group", ElGamalMessagePropertySuite(t, edwards25519.NewPrimeSubGroup()).CheckAll)
}

func TestElGamalCommitmentProperties(t *testing.T) {
	t.Parallel()
	t.Run("k256 group", ElGamalCommitmentGeneratorPropertySuite(t, k256.NewCurve()).CheckAll)
	t.Run("edwards25519 group", ElGamalCommitmentGeneratorPropertySuite(t, edwards25519.NewPrimeSubGroup()).CheckAll)
}
