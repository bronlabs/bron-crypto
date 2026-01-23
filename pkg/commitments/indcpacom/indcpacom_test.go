package indcpacom_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/commitments/indcpacom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
)

func TestBasicCommitmentAndVerification(t *testing.T) {
	t.Parallel()

	scheme, pk := setupScheme(t)

	// Create a message
	plaintext := sampleMessage(t, pk)
	message, err := indcpacom.NewMessage(plaintext)
	require.NoError(t, err)

	// Commit to the message
	committer, err := scheme.Committer()
	require.NoError(t, err)
	commitment, witness, err := committer.Commit(message, pcg.NewRandomised())
	require.NoError(t, err)
	require.NotNil(t, commitment)
	require.NotNil(t, witness)

	// Verify the commitment
	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	err = verifier.Verify(commitment, message, witness)
	require.NoError(t, err, "commitment should verify")
}

func TestCommitWithWitness(t *testing.T) {
	t.Parallel()

	scheme, pk := setupScheme(t)

	// Create a message
	plaintext := sampleMessage(t, pk)
	message, err := indcpacom.NewMessage(plaintext)
	require.NoError(t, err)

	// Sample a nonce and create a witness directly
	nonce, err := pk.NonceSpace().Sample(pcg.NewRandomised())
	require.NoError(t, err)
	witness, err := indcpacom.NewWitness(nonce)
	require.NoError(t, err)

	// Commit with the witness
	committer, err := scheme.Committer()
	require.NoError(t, err)
	commitment1, err := committer.CommitWithWitness(message, witness)
	require.NoError(t, err)

	// Commit with the same witness should produce the same commitment
	commitment2, err := committer.CommitWithWitness(message, witness)
	require.NoError(t, err)
	require.True(t, commitment1.Equal(commitment2), "deterministic commitment should match")

	// Verify both commitments
	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	err = verifier.Verify(commitment1, message, witness)
	require.NoError(t, err)
	err = verifier.Verify(commitment2, message, witness)
	require.NoError(t, err)
}

func TestVerificationFailsWithWrongMessage(t *testing.T) {
	t.Parallel()

	scheme, pk := setupScheme(t)

	// Create two different messages
	plaintext1 := sampleMessage(t, pk)
	plaintext2 := sampleMessage(t, pk)
	message1, err := indcpacom.NewMessage(plaintext1)
	require.NoError(t, err)
	message2, err := indcpacom.NewMessage(plaintext2)
	require.NoError(t, err)

	// Commit to the first message
	committer, err := scheme.Committer()
	require.NoError(t, err)
	commitment, witness, err := committer.Commit(message1, pcg.NewRandomised())
	require.NoError(t, err)

	// Verification should fail with wrong message
	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	err = verifier.Verify(commitment, message2, witness)
	require.Error(t, err, "verification should fail with wrong message")
}

func TestVerificationFailsWithWrongWitness(t *testing.T) {
	t.Parallel()

	scheme, pk := setupScheme(t)

	// Create a message
	plaintext := sampleMessage(t, pk)
	message, err := indcpacom.NewMessage(plaintext)
	require.NoError(t, err)

	// Commit to the message twice with different witnesses
	committer, err := scheme.Committer()
	require.NoError(t, err)
	commitment1, witness1, err := committer.Commit(message, pcg.NewRandomised())
	require.NoError(t, err)
	_, witness2, err := committer.Commit(message, pcg.NewRandomised())
	require.NoError(t, err)

	// Verification should fail with wrong witness
	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	err = verifier.Verify(commitment1, message, witness2)
	require.Error(t, err, "verification should fail with wrong witness")

	// But verification should succeed with correct witness
	err = verifier.Verify(commitment1, message, witness1)
	require.NoError(t, err)
}

func TestReRandomization(t *testing.T) {
	t.Parallel()

	scheme, pk := setupScheme(t)
	key, err := indcpacom.NewKey(pk)
	require.NoError(t, err)

	// Create a message and commit
	plaintext := sampleMessage(t, pk)
	message, err := indcpacom.NewMessage(plaintext)
	require.NoError(t, err)

	committer, err := scheme.Committer()
	require.NoError(t, err)
	commitment1, witness1, err := committer.Commit(message, pcg.NewRandomised())
	require.NoError(t, err)

	// Re-randomise the commitment
	commitment2, rerandWitness, err := commitment1.ReRandomise(key, pcg.NewRandomised())
	require.NoError(t, err)
	require.NotNil(t, commitment2)
	require.NotNil(t, rerandWitness)

	// Re-randomised commitment should be different
	require.False(t, commitment1.Equal(commitment2), "re-randomised commitment should be different")

	// The original commitment should still verify with original witness
	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	err = verifier.Verify(commitment1, message, witness1)
	require.NoError(t, err)

	// The re-randomised commitment should verify with combined witness
	combinedWitness := witness1.Op(rerandWitness)
	err = verifier.Verify(commitment2, message, combinedWitness)
	require.NoError(t, err, "re-randomised commitment should verify with combined witness")
}

func TestReRandomizationWithWitness(t *testing.T) {
	t.Parallel()

	scheme, pk := setupScheme(t)
	key, err := indcpacom.NewKey(pk)
	require.NoError(t, err)

	// Create a message and commit
	plaintext := sampleMessage(t, pk)
	message, err := indcpacom.NewMessage(plaintext)
	require.NoError(t, err)

	committer, err := scheme.Committer()
	require.NoError(t, err)
	commitment1, _, err := committer.Commit(message, pcg.NewRandomised())
	require.NoError(t, err)

	// Sample a specific nonce for re-randomization and create witness directly
	rerandNonce, err := pk.NonceSpace().Sample(pcg.NewRandomised())
	require.NoError(t, err)
	rerandWitness, err := indcpacom.NewWitness(rerandNonce)
	require.NoError(t, err)

	// Re-randomise with specific witness twice - should produce same result
	commitment2, err := commitment1.ReRandomiseWithWitness(key, rerandWitness)
	require.NoError(t, err)

	commitment3, err := commitment1.ReRandomiseWithWitness(key, rerandWitness)
	require.NoError(t, err)

	// Same witness should produce same re-randomised commitment
	require.True(t, commitment2.Equal(commitment3), "deterministic re-randomization should match")
}

func TestMultipleReRandomizations(t *testing.T) {
	t.Parallel()

	scheme, pk := setupScheme(t)
	key, err := indcpacom.NewKey(pk)
	require.NoError(t, err)

	// Create a message and commit
	plaintext := sampleMessage(t, pk)
	message, err := indcpacom.NewMessage(plaintext)
	require.NoError(t, err)

	committer, err := scheme.Committer()
	require.NoError(t, err)
	commitment0, witness0, err := committer.Commit(message, pcg.NewRandomised())
	require.NoError(t, err)

	// Re-randomise multiple times, tracking witnesses
	commitment1, rerandWitness1, err := commitment0.ReRandomise(key, pcg.NewRandomised())
	require.NoError(t, err)
	commitment2, rerandWitness2, err := commitment1.ReRandomise(key, pcg.NewRandomised())
	require.NoError(t, err)
	commitment3, rerandWitness3, err := commitment2.ReRandomise(key, pcg.NewRandomised())
	require.NoError(t, err)

	// All commitments should be different
	require.False(t, commitment0.Equal(commitment1))
	require.False(t, commitment1.Equal(commitment2))
	require.False(t, commitment2.Equal(commitment3))
	require.False(t, commitment0.Equal(commitment3))

	// Verify each commitment with cumulative combined witness
	verifier, err := scheme.Verifier()
	require.NoError(t, err)

	// commitment0 verifies with witness0
	err = verifier.Verify(commitment0, message, witness0)
	require.NoError(t, err)

	// commitment1 verifies with witness0.Op(rerandWitness1)
	witness1 := witness0.Op(rerandWitness1)
	err = verifier.Verify(commitment1, message, witness1)
	require.NoError(t, err)

	// commitment2 verifies with witness1.Op(rerandWitness2)
	witness2 := witness1.Op(rerandWitness2)
	err = verifier.Verify(commitment2, message, witness2)
	require.NoError(t, err)

	// commitment3 verifies with witness2.Op(rerandWitness3)
	witness3 := witness2.Op(rerandWitness3)
	err = verifier.Verify(commitment3, message, witness3)
	require.NoError(t, err)
}

func TestNilInputErrors(t *testing.T) {
	t.Parallel()

	scheme, pk := setupScheme(t)

	plaintext := sampleMessage(t, pk)
	message, err := indcpacom.NewMessage(plaintext)
	require.NoError(t, err)

	committer, err := scheme.Committer()
	require.NoError(t, err)

	t.Run("commit with nil message", func(t *testing.T) {
		t.Parallel()
		_, _, err := committer.Commit(nil, pcg.NewRandomised())
		require.Error(t, err)
	})

	t.Run("commit with nil prng", func(t *testing.T) {
		t.Parallel()
		_, _, err := committer.Commit(message, nil)
		require.Error(t, err)
	})

	t.Run("commit with witness nil message", func(t *testing.T) {
		t.Parallel()
		_, witness, err := committer.Commit(message, pcg.NewRandomised())
		require.NoError(t, err)
		_, err = committer.CommitWithWitness(nil, witness)
		require.Error(t, err)
	})

	t.Run("commit with witness nil witness", func(t *testing.T) {
		t.Parallel()
		_, err := committer.CommitWithWitness(message, nil)
		require.Error(t, err)
	})

	t.Run("new message with nil", func(t *testing.T) {
		t.Parallel()
		_, err := indcpacom.NewMessage[*paillier.Plaintext](nil)
		require.Error(t, err)
	})

	t.Run("new key with nil", func(t *testing.T) {
		t.Parallel()
		_, err := indcpacom.NewKey[*paillier.PublicKey](nil)
		require.Error(t, err)
	})

	t.Run("new witness with nil", func(t *testing.T) {
		t.Parallel()
		_, err := indcpacom.NewWitness[*paillier.Nonce](nil)
		require.Error(t, err)
	})
}

func TestReRandomizeNilInputErrors(t *testing.T) {
	t.Parallel()

	scheme, pk := setupScheme(t)
	key, err := indcpacom.NewKey(pk)
	require.NoError(t, err)

	plaintext := sampleMessage(t, pk)
	message, err := indcpacom.NewMessage(plaintext)
	require.NoError(t, err)

	committer, err := scheme.Committer()
	require.NoError(t, err)
	commitment, witness, err := committer.Commit(message, pcg.NewRandomised())
	require.NoError(t, err)

	t.Run("re-randomise with nil key", func(t *testing.T) {
		t.Parallel()
		_, _, err := commitment.ReRandomise(nil, pcg.NewRandomised())
		require.Error(t, err)
	})

	t.Run("re-randomise with nil prng", func(t *testing.T) {
		t.Parallel()
		_, _, err := commitment.ReRandomise(key, nil)
		require.Error(t, err)
	})

	t.Run("re-randomise with witness nil key", func(t *testing.T) {
		t.Parallel()
		_, err := commitment.ReRandomiseWithWitness(nil, witness)
		require.Error(t, err)
	})

	t.Run("re-randomise with witness nil witness", func(t *testing.T) {
		t.Parallel()
		_, err := commitment.ReRandomiseWithWitness(key, nil)
		require.Error(t, err)
	})
}

func TestSchemeName(t *testing.T) {
	t.Parallel()

	scheme, _ := setupScheme(t)
	name := scheme.Name()
	require.Contains(t, string(name), "IND-CPA-Com")
	require.Contains(t, string(name), "paillier")
}

func TestCommitmentEquality(t *testing.T) {
	t.Parallel()

	scheme, pk := setupScheme(t)

	plaintext := sampleMessage(t, pk)
	message, err := indcpacom.NewMessage(plaintext)
	require.NoError(t, err)

	committer, err := scheme.Committer()
	require.NoError(t, err)

	// Get a commitment and its witness
	commitment1, witness1, err := committer.Commit(message, pcg.NewRandomised())
	require.NoError(t, err)

	// Same commitment should be equal to itself
	require.True(t, commitment1.Equal(commitment1))

	// Commitment created with same witness should be equal
	commitment2, err := committer.CommitWithWitness(message, witness1)
	require.NoError(t, err)
	require.True(t, commitment1.Equal(commitment2))

	// Different commitment should not be equal
	commitment3, _, err := committer.Commit(message, pcg.NewRandomised())
	require.NoError(t, err)
	require.False(t, commitment1.Equal(commitment3))
}

func TestCommitmentValue(t *testing.T) {
	t.Parallel()

	scheme, pk := setupScheme(t)

	plaintext := sampleMessage(t, pk)
	message, err := indcpacom.NewMessage(plaintext)
	require.NoError(t, err)

	committer, err := scheme.Committer()
	require.NoError(t, err)

	commitment, _, err := committer.Commit(message, pcg.NewRandomised())
	require.NoError(t, err)

	// Value() should return the underlying ciphertext
	value := commitment.Value()
	require.NotNil(t, value)
}

func TestKeyValue(t *testing.T) {
	t.Parallel()

	_, pk := setupScheme(t)
	key, err := indcpacom.NewKey(pk)
	require.NoError(t, err)

	// Value() should return the underlying public key
	value := key.Value()
	require.NotNil(t, value)
	require.Equal(t, pk, value)
}

func TestMessageValue(t *testing.T) {
	t.Parallel()

	_, pk := setupScheme(t)
	plaintext := sampleMessage(t, pk)

	message, err := indcpacom.NewMessage(plaintext)
	require.NoError(t, err)

	// Value() should return the underlying plaintext
	value := message.Value()
	require.NotNil(t, value)
	require.True(t, plaintext.Equal(value))
}

func TestWitnessValue(t *testing.T) {
	t.Parallel()

	_, pk := setupScheme(t)

	// Sample a nonce and create a witness
	nonce, err := pk.NonceSpace().Sample(pcg.NewRandomised())
	require.NoError(t, err)
	witness, err := indcpacom.NewWitness(nonce)
	require.NoError(t, err)

	// Value() should return the underlying nonce
	value := witness.Value()
	require.NotNil(t, value)
	require.Equal(t, nonce, value)
}

func TestWitnessOp(t *testing.T) {
	t.Parallel()

	_, pk := setupScheme(t)

	// Sample two nonces and create witnesses
	nonce1, err := pk.NonceSpace().Sample(pcg.NewRandomised())
	require.NoError(t, err)
	witness1, err := indcpacom.NewWitness(nonce1)
	require.NoError(t, err)

	nonce2, err := pk.NonceSpace().Sample(pcg.NewRandomised())
	require.NoError(t, err)
	witness2, err := indcpacom.NewWitness(nonce2)
	require.NoError(t, err)

	// Combine witnesses
	combined := witness1.Op(witness2)
	require.NotNil(t, combined)

	// Combined witness should have the combined nonce value
	expectedNonce := nonce1.Op(nonce2)
	require.True(t, expectedNonce.Equal(combined.Value()))
}

// Helper functions

func setupScheme(tb testing.TB) (
	*indcpacom.Scheme[
		*paillier.PrivateKey, *paillier.PublicKey, *paillier.Plaintext,
		*paillier.Ciphertext, *paillier.Nonce,
		*paillier.KeyGenerator, *paillier.Encrypter, *paillier.Decrypter,
	],
	*paillier.PublicKey,
) {
	tb.Helper()

	paillierScheme := paillier.NewScheme()
	_, pk := sampleKeys(tb, pcg.NewRandomised())

	key, err := indcpacom.NewKey(pk)
	require.NoError(tb, err)

	scheme, err := indcpacom.NewScheme(paillierScheme, key)
	require.NoError(tb, err)

	return scheme, pk
}

func sampleKeys(tb testing.TB, prng io.Reader) (*paillier.PrivateKey, *paillier.PublicKey) {
	tb.Helper()
	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen()
	require.NoError(tb, err)
	sk, pk, err := kg.Generate(prng)
	require.NoError(tb, err)
	return sk, pk
}

func sampleMessage(tb testing.TB, pk *paillier.PublicKey) *paillier.Plaintext {
	tb.Helper()
	pts := pk.PlaintextSpace()
	pt, err := pts.Sample(nil, nil, pcg.NewRandomised())
	require.NoError(tb, err)
	return pt
}
