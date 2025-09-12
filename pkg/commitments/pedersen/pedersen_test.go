package pedersen_test

import (
	"bytes"
	crand "crypto/rand"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/stretchr/testify/require"
)

func TestBasicCommitment(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()
	h, err := curve.Hash([]byte("pedersen-test-h"))
	require.NoError(t, err)

	// Create commitment key
	key, err := pedersen.NewCommitmentKey(g, h)
	require.NoError(t, err, "could not create key")

	// Create scheme
	scheme, err := pedersen.NewScheme(key)
	require.NoError(t, err, "could not create scheme")
	require.Equal(t, pedersen.Name, scheme.Name())

	// Create a message
	message := pedersen.NewMessage(field.FromUint64(42))

	// Commit to the message
	committer := scheme.Committer()
	commitment, witness, err := committer.Commit(message, crand.Reader)
	require.NoError(t, err, "could not commit")
	require.NotNil(t, commitment)
	require.NotNil(t, witness)
	require.False(t, witness.Value().IsZero(), "witness should not be zero")

	// Verify the commitment
	verifier := scheme.Verifier()
	err = verifier.Verify(commitment, message, witness)
	verified := err == nil
	require.True(t, verified, "commitment should verify")

	// Verify with wrong message
	wrongMessage := pedersen.NewMessage(field.FromUint64(43))
	err = verifier.Verify(commitment, wrongMessage, witness)
	verified = err == nil
	require.False(t, verified, "commitment should not verify with wrong message")

	// Verify with wrong witness
	wrongWitness, err := pedersen.NewWitness(field.FromUint64(999))
	require.NoError(t, err)
	err = verifier.Verify(commitment, message, wrongWitness)
	verified = err == nil
	require.False(t, verified, "commitment should not verify with wrong witness")
}

func TestCommitmentKeyCreation(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	g := curve.Generator()
	h, err := curve.Hash([]byte("test-h"))
	require.NoError(t, err)

	t.Run("valid key creation", func(t *testing.T) {
		key, err := pedersen.NewCommitmentKey(g, h)
		require.NoError(t, err)
		require.NotNil(t, key)
		require.True(t, g.Equal(key.G()))
		require.True(t, h.Equal(key.H()))
	})

	t.Run("g is identity", func(t *testing.T) {
		identity := curve.OpIdentity()
		_, err := pedersen.NewCommitmentKey(identity, h)
		require.Error(t, err)
		require.Contains(t, err.Error(), "identity")
	})

	t.Run("h is identity", func(t *testing.T) {
		identity := curve.OpIdentity()
		_, err := pedersen.NewCommitmentKey(g, identity)
		require.Error(t, err)
		require.Contains(t, err.Error(), "identity")
	})

	t.Run("g equals h", func(t *testing.T) {
		_, err := pedersen.NewCommitmentKey(g, g)
		require.Error(t, err)
		require.Contains(t, err.Error(), "cannot be equal")
	})

	t.Run("key serialization", func(t *testing.T) {
		key, err := pedersen.NewCommitmentKey(g, h)
		require.NoError(t, err)

		// Serialize
		keyBytes := key.Bytes()
		require.Equal(t, 2*curve.ElementSize(), len(keyBytes))

		// Deserialize
		key2, err := pedersen.NewCommitmentKeyFromBytes(curve, keyBytes)
		require.NoError(t, err)
		require.True(t, key.G().Equal(key2.G()))
		require.True(t, key.H().Equal(key2.H()))
	})

	t.Run("key deserialization with wrong size", func(t *testing.T) {
		wrongBytes := make([]byte, curve.ElementSize()) // Only one element instead of two
		_, err := pedersen.NewCommitmentKeyFromBytes(curve, wrongBytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "input length")
	})
}

func TestCommitmentCreation(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()
	h, err := curve.Hash([]byte("test-h-commitment"))
	require.NoError(t, err)

	key, err := pedersen.NewCommitmentKey(g, h)
	require.NoError(t, err)
	scheme, err := pedersen.NewScheme(key)
	require.NoError(t, err)
	committer := scheme.Committer()

	t.Run("nil message", func(t *testing.T) {
		_, _, err := committer.Commit(nil, crand.Reader)
		require.Error(t, err)
		require.Contains(t, err.Error(), "message cannot be nil")
	})

	t.Run("nil prng", func(t *testing.T) {
		message := pedersen.NewMessage(field.FromUint64(42))
		_, _, err := committer.Commit(message, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "prng cannot be nil")
	})

	t.Run("commit with witness", func(t *testing.T) {
		message := pedersen.NewMessage(field.FromUint64(42))
		witness, err := pedersen.NewWitness(field.FromUint64(123))
		require.NoError(t, err)

		commitment, err := committer.CommitWithWitness(message, witness)
		require.NoError(t, err)
		require.NotNil(t, commitment)

		// Verify
		verifier := scheme.Verifier()
		err = verifier.Verify(commitment, message, witness)
		verified := err == nil
		require.True(t, verified)
	})

	t.Run("commit with witness nil message", func(t *testing.T) {
		witness, err := pedersen.NewWitness(field.FromUint64(123))
		require.NoError(t, err)

		_, err = committer.CommitWithWitness(nil, witness)
		require.Error(t, err)
		require.Contains(t, err.Error(), "message cannot be nil")
	})

	t.Run("commit with witness nil witness", func(t *testing.T) {
		message := pedersen.NewMessage(field.FromUint64(42))
		_, err := committer.CommitWithWitness(message, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "witness cannot be nil")
	})

	t.Run("deterministic commitment", func(t *testing.T) {
		message := pedersen.NewMessage(field.FromUint64(42))

		// Use deterministic randomness
		seed := []byte("deterministic seed for testing only!")
		prng1 := bytes.NewReader(append(seed, make([]byte, 64)...))
		prng2 := bytes.NewReader(append(seed, make([]byte, 64)...))

		commitment1, witness1, err := committer.Commit(message, prng1)
		require.NoError(t, err)

		commitment2, witness2, err := committer.Commit(message, prng2)
		require.NoError(t, err)

		// Same randomness should produce same commitment and witness
		require.True(t, commitment1.Equal(commitment2))
		require.True(t, witness1.Equal(witness2))
	})
}

func TestWitnessCreation(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	t.Run("valid witness", func(t *testing.T) {
		witness, err := pedersen.NewWitness(field.FromUint64(123))
		require.NoError(t, err)
		require.NotNil(t, witness)
		require.True(t, field.FromUint64(123).Equal(witness.Value()))
	})

	t.Run("zero witness", func(t *testing.T) {
		_, err := pedersen.NewWitness(field.Zero())
		require.Error(t, err)
		require.Contains(t, err.Error(), "witness value cannot be zero")
	})

	t.Run("witness operations", func(t *testing.T) {
		w1, err := pedersen.NewWitness(field.FromUint64(10))
		require.NoError(t, err)
		w2, err := pedersen.NewWitness(field.FromUint64(20))
		require.NoError(t, err)

		// Add
		w3 := w1.Add(w2)
		require.True(t, field.FromUint64(30).Equal(w3.Value()))

		// Op (same as Add)
		w4 := w1.Op(w2)
		require.True(t, w3.Equal(w4))

		// Mul
		w5 := w1.Mul(w2)
		require.True(t, field.FromUint64(200).Equal(w5.Value()))

		// OtherOp (same as Mul)
		w6 := w1.OtherOp(w2)
		require.True(t, w5.Equal(w6))

		// Clone
		w7 := w1.Clone()
		require.True(t, w1.Equal(w7))
		require.False(t, w1 == w7) // Different pointers

		// Equal
		require.True(t, w1.Equal(w1))
		require.False(t, w1.Equal(w2))
		require.False(t, w1.Equal(nil))

		// HashCode
		require.Equal(t, w1.HashCode(), w7.HashCode())
		require.NotEqual(t, w1.HashCode(), w2.HashCode())
	})
}

func TestMessageOperations(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	t.Run("message creation and operations", func(t *testing.T) {
		m1 := pedersen.NewMessage(field.FromUint64(10))
		m2 := pedersen.NewMessage(field.FromUint64(20))

		require.True(t, field.FromUint64(10).Equal(m1.Value()))

		// Add
		m3 := m1.Add(m2)
		require.True(t, field.FromUint64(30).Equal(m3.Value()))

		// Op (same as Add)
		m4 := m1.Op(m2)
		require.True(t, m3.Equal(m4))

		// Mul
		m5 := m1.Mul(m2)
		require.True(t, field.FromUint64(200).Equal(m5.Value()))

		// OtherOp (same as Mul)
		m6 := m1.OtherOp(m2)
		require.True(t, m5.Equal(m6))

		// Clone
		m7 := m1.Clone()
		require.True(t, m1.Equal(m7))
		require.False(t, m1 == m7) // Different pointers

		// Equal
		require.True(t, m1.Equal(m1))
		require.False(t, m1.Equal(m2))
		require.False(t, m1.Equal(nil))

		// HashCode
		require.Equal(t, m1.HashCode(), m7.HashCode())
		require.NotEqual(t, m1.HashCode(), m2.HashCode())
	})

	t.Run("nil operations", func(t *testing.T) {
		m1 := pedersen.NewMessage(field.FromUint64(10))

		// Operations with nil
		m2 := m1.Add(nil)
		require.True(t, m1.Equal(m2))

		m3 := m1.Mul(nil)
		require.True(t, m1.Equal(m3))

		// Clone of nil
		var nilMsg *pedersen.Message[*k256.Scalar]
		cloned := nilMsg.Clone()
		require.Nil(t, cloned)
	})
}

func TestHomomorphicProperties(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()
	h, err := curve.Hash([]byte("test-h-homomorphic"))
	require.NoError(t, err)

	key, err := pedersen.NewCommitmentKey(g, h)
	require.NoError(t, err)
	scheme, err := pedersen.NewScheme(key)
	require.NoError(t, err)
	committer := scheme.Committer()
	verifier := scheme.Verifier()

	t.Run("additive homomorphism", func(t *testing.T) {
		// Create two messages
		m1 := pedersen.NewMessage(field.FromUint64(10))
		m2 := pedersen.NewMessage(field.FromUint64(20))

		// Commit to each message
		c1, w1, err := committer.Commit(m1, crand.Reader)
		require.NoError(t, err)
		c2, w2, err := committer.Commit(m2, crand.Reader)
		require.NoError(t, err)

		// Add commitments: C(m1) + C(m2)
		c3 := c1.Op(c2)

		// Add messages and witnesses: m3 = m1 + m2, w3 = w1 + w2
		m3 := m1.Add(m2)
		w3 := w1.Add(w2)

		// Verify that C(m1) + C(m2) = C(m1 + m2) with witness w1 + w2
		err = verifier.Verify(c3, m3, w3)
		require.NoError(t, err, "additive homomorphism should hold")

		// Also verify by committing to the sum directly
		c4, err := committer.CommitWithWitness(m3, w3)
		require.NoError(t, err)
		require.True(t, c3.Equal(c4), "homomorphic addition should equal direct commitment")
	})

	t.Run("scalar multiplication", func(t *testing.T) {
		// Create a message and scalar
		m := pedersen.NewMessage(field.FromUint64(10))
		scalar := pedersen.NewMessage(field.FromUint64(3))

		// Commit to the message
		c, w, err := committer.Commit(m, crand.Reader)
		require.NoError(t, err)

		// Multiply commitment by scalar: scalar * C(m)
		cScaled := c.ScalarOp(scalar)

		// Multiply message and witness by scalar
		mScaled := pedersen.NewMessage(field.FromUint64(30)) // 10 * 3
		wScaled := &pedersen.Witness[*k256.Scalar]{}         // Can't directly multiply witness by scalar due to internal field
		// We need to compute w * 3
		wValue := w.Value()
		wScaledValue := wValue.Mul(scalar.Value())
		wScaled, err = pedersen.NewWitness(wScaledValue)
		require.NoError(t, err)

		// Verify that scalar * C(m) = C(scalar * m) with witness scalar * w
		err = verifier.Verify(cScaled, mScaled, wScaled)
		require.NoError(t, err, "scalar multiplication should hold")
	})

	t.Run("combined operations", func(t *testing.T) {
		// Test: 2*C(m1) + 3*C(m2) = C(2*m1 + 3*m2)
		m1 := pedersen.NewMessage(field.FromUint64(10))
		m2 := pedersen.NewMessage(field.FromUint64(20))

		c1, w1, err := committer.Commit(m1, crand.Reader)
		require.NoError(t, err)
		c2, w2, err := committer.Commit(m2, crand.Reader)
		require.NoError(t, err)

		// Scale commitments
		scalar1 := pedersen.NewMessage(field.FromUint64(2))
		scalar2 := pedersen.NewMessage(field.FromUint64(3))

		c1Scaled := c1.ScalarOp(scalar1)
		c2Scaled := c2.ScalarOp(scalar2)

		// Add scaled commitments
		cCombined := c1Scaled.Op(c2Scaled)

		// Compute combined message: 2*10 + 3*20 = 80
		mCombined := pedersen.NewMessage(field.FromUint64(80))

		// Compute combined witness
		w1Scaled, err := pedersen.NewWitness(w1.Value().Mul(scalar1.Value()))
		require.NoError(t, err)
		w2Scaled, err := pedersen.NewWitness(w2.Value().Mul(scalar2.Value()))
		require.NoError(t, err)
		wCombined := w1Scaled.Add(w2Scaled)

		// Verify
		err = verifier.Verify(cCombined, mCombined, wCombined)
		require.NoError(t, err, "combined operations should hold")
	})
}

func TestReRandomization(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()
	h, err := curve.Hash([]byte("test-h-rerandom"))
	require.NoError(t, err)

	key, err := pedersen.NewCommitmentKey(g, h)
	require.NoError(t, err)
	scheme, err := pedersen.NewScheme(key)
	require.NoError(t, err)
	committer := scheme.Committer()
	verifier := scheme.Verifier()

	t.Run("re-randomization preserves message", func(t *testing.T) {
		message := pedersen.NewMessage(field.FromUint64(42))

		// Initial commitment
		c1, w1, err := committer.Commit(message, crand.Reader)
		require.NoError(t, err)

		// Re-randomize
		c2, r, err := c1.ReRandomise(key, crand.Reader)
		require.NoError(t, err)
		require.NotNil(t, c2)
		require.NotNil(t, r)
		require.False(t, c1.Equal(c2), "re-randomized commitment should be different")

		// The new witness is w1 + r
		w2 := w1.Add(r)

		// Verify with new commitment and witness
		err = verifier.Verify(c2, message, w2)
		require.NoError(t, err, "re-randomized commitment should verify")

		// Original commitment should still verify with original witness
		err = verifier.Verify(c1, message, w1)
		require.NoError(t, err, "original commitment should still verify")
	})

	t.Run("re-randomization with specific witness", func(t *testing.T) {
		message := pedersen.NewMessage(field.FromUint64(42))

		// Initial commitment
		c1, w1, err := committer.Commit(message, crand.Reader)
		require.NoError(t, err)

		// Create specific re-randomization witness
		r, err := pedersen.NewWitness(field.FromUint64(777))
		require.NoError(t, err)

		// Re-randomize with specific witness
		c2, err := c1.ReRandomiseWith(key, r)
		require.NoError(t, err)

		// The new witness is w1 + r
		w2 := w1.Add(r)

		// Verify
		err = verifier.Verify(c2, message, w2)
		require.NoError(t, err)
	})

	t.Run("re-randomization errors", func(t *testing.T) {
		message := pedersen.NewMessage(field.FromUint64(42))
		c, _, err := committer.Commit(message, crand.Reader)
		require.NoError(t, err)

		// Nil key
		_, _, err = c.ReRandomise(nil, crand.Reader)
		require.Error(t, err)
		require.Contains(t, err.Error(), "key cannot be nil")

		// Nil prng
		_, _, err = c.ReRandomise(key, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "prng cannot be nil")

		// ReRandomiseWith with nil witness
		_, err = c.ReRandomiseWith(key, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "witness cannot be nil")

		// ReRandomiseWith with nil key
		r, err := pedersen.NewWitness(field.FromUint64(123))
		require.NoError(t, err)
		_, err = c.ReRandomiseWith(nil, r)
		require.Error(t, err)
		require.Contains(t, err.Error(), "key cannot be nil")
	})

	t.Run("multiple re-randomizations", func(t *testing.T) {
		message := pedersen.NewMessage(field.FromUint64(42))

		// Initial commitment
		c0, w0, err := committer.Commit(message, crand.Reader)
		require.NoError(t, err)

		// Re-randomize multiple times
		c1, r1, err := c0.ReRandomise(key, crand.Reader)
		require.NoError(t, err)
		c2, r2, err := c1.ReRandomise(key, crand.Reader)
		require.NoError(t, err)
		c3, r3, err := c2.ReRandomise(key, crand.Reader)
		require.NoError(t, err)

		// All commitments should be different
		require.False(t, c0.Equal(c1))
		require.False(t, c1.Equal(c2))
		require.False(t, c2.Equal(c3))

		// Final witness is w0 + r1 + r2 + r3
		wFinal := w0.Add(r1).Add(r2).Add(r3)

		// Verify final commitment
		err = verifier.Verify(c3, message, wFinal)
		require.NoError(t, err)
	})
}

func TestCommitmentOperations(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()
	h, err := curve.Hash([]byte("test-h-ops"))
	require.NoError(t, err)

	key, err := pedersen.NewCommitmentKey(g, h)
	require.NoError(t, err)
	scheme, err := pedersen.NewScheme(key)
	require.NoError(t, err)
	committer := scheme.Committer()

	t.Run("commitment creation", func(t *testing.T) {
		// Create from group element
		elem := g.ScalarOp(field.FromUint64(123))
		c, err := pedersen.NewCommitment(elem)
		require.NoError(t, err)
		require.True(t, elem.Equal(c.Value()))

		// Cannot create from identity
		_, err = pedersen.NewCommitment(curve.OpIdentity())
		require.Error(t, err)
		require.Contains(t, err.Error(), "identity")
	})

	t.Run("commitment operations", func(t *testing.T) {
		m1 := pedersen.NewMessage(field.FromUint64(10))
		m2 := pedersen.NewMessage(field.FromUint64(20))

		c1, _, err := committer.Commit(m1, crand.Reader)
		require.NoError(t, err)
		c2, _, err := committer.Commit(m2, crand.Reader)
		require.NoError(t, err)

		// Op (group operation)
		c3 := c1.Op(c2)
		require.NotNil(t, c3)
		require.False(t, c3.Equal(c1))
		require.False(t, c3.Equal(c2))

		// Op with nil
		c4 := c1.Op(nil)
		require.True(t, c1.Equal(c4))

		// Clone
		c5 := c1.Clone()
		require.True(t, c1.Equal(c5))
		require.False(t, c1 == c5) // Different pointers

		// Clone of nil
		var nilCommit *pedersen.Commitment[*k256.Point, *k256.Scalar]
		cloned := nilCommit.Clone()
		require.Nil(t, cloned)

		// Equal
		require.True(t, c1.Equal(c1))
		require.False(t, c1.Equal(c2))
		require.False(t, c1.Equal(nil))

		// HashCode
		require.Equal(t, c1.HashCode(), c5.HashCode())
		require.NotEqual(t, c1.HashCode(), c2.HashCode())
	})

	t.Run("scalar operation", func(t *testing.T) {
		m := pedersen.NewMessage(field.FromUint64(10))
		c, _, err := committer.Commit(m, crand.Reader)
		require.NoError(t, err)

		scalar := pedersen.NewMessage(field.FromUint64(3))
		cScaled := c.ScalarOp(scalar)
		require.NotNil(t, cScaled)
		require.False(t, c.Equal(cScaled))

		// ScalarOp with nil
		cScaled2 := c.ScalarOp(nil)
		require.True(t, c.Equal(cScaled2))
	})
}

func TestEdgeCases(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()
	h, err := curve.Hash([]byte("test-h-edge"))
	require.NoError(t, err)

	key, err := pedersen.NewCommitmentKey(g, h)
	require.NoError(t, err)
	scheme, err := pedersen.NewScheme(key)
	require.NoError(t, err)

	t.Run("nil scheme creation", func(t *testing.T) {
		_, err := pedersen.NewScheme[*k256.Point, *k256.Scalar](nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "key cannot be nil")
	})

	t.Run("short random source", func(t *testing.T) {
		committer := scheme.Committer()
		message := pedersen.NewMessage(field.FromUint64(42))

		// Provide insufficient randomness
		shortRandom := bytes.NewReader([]byte{1, 2, 3}) // Too short
		_, _, err := committer.Commit(message, shortRandom)
		require.Error(t, err)
		require.Contains(t, err.Error(), "[RANDOM_SAMPLE_ERROR]")
	})

	t.Run("commitment to zero message", func(t *testing.T) {
		committer := scheme.Committer()
		verifier := scheme.Verifier()

		// Commitment to zero is valid
		zeroMessage := pedersen.NewMessage(field.Zero())
		c, w, err := committer.Commit(zeroMessage, crand.Reader)
		require.NoError(t, err)

		// Should verify
		err = verifier.Verify(c, zeroMessage, w)
		require.NoError(t, err)
	})
}

func TestMultipleCurves(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		curve := k256.NewCurve()
		field := k256.NewScalarField()
		g := curve.Generator()
		h, err := curve.Hash([]byte("test-k256"))
		require.NoError(t, err)

		// Create key and scheme
		key, err := pedersen.NewCommitmentKey(g, h)
		require.NoError(t, err)
		scheme, err := pedersen.NewScheme(key)
		require.NoError(t, err)

		// Test basic commitment
		committer := scheme.Committer()
		verifier := scheme.Verifier()

		message := pedersen.NewMessage(field.FromUint64(42))
		commitment, witness, err := committer.Commit(message, crand.Reader)
		require.NoError(t, err)

		err = verifier.Verify(commitment, message, witness)
		verified := err == nil
		require.True(t, verified)
	})

	t.Run("bls12381", func(t *testing.T) {
		curve := bls12381.NewG1()
		field := bls12381.NewScalarField()
		g := curve.Generator()
		h, err := curve.Hash([]byte("test-bls12381"))
		require.NoError(t, err)

		// Create key and scheme
		key, err := pedersen.NewCommitmentKey(g, h)
		require.NoError(t, err)
		scheme, err := pedersen.NewScheme(key)
		require.NoError(t, err)

		// Test basic commitment
		committer := scheme.Committer()
		verifier := scheme.Verifier()

		message := pedersen.NewMessage(field.FromUint64(42))
		commitment, witness, err := committer.Commit(message, crand.Reader)
		require.NoError(t, err)

		err = verifier.Verify(commitment, message, witness)
		verified := err == nil
		require.True(t, verified)
	})
}

// Benchmarks

func BenchmarkCommit(b *testing.B) {
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()
	h, err := curve.Hash([]byte("bench-h"))
	require.NoError(b, err)

	key, err := pedersen.NewCommitmentKey(g, h)
	require.NoError(b, err)
	scheme, err := pedersen.NewScheme(key)
	require.NoError(b, err)
	committer := scheme.Committer()

	message := pedersen.NewMessage(field.FromUint64(42))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := committer.Commit(message, crand.Reader)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()
	h, err := curve.Hash([]byte("bench-h-verify"))
	require.NoError(b, err)

	key, err := pedersen.NewCommitmentKey(g, h)
	require.NoError(b, err)
	scheme, err := pedersen.NewScheme(key)
	require.NoError(b, err)
	committer := scheme.Committer()
	verifier := scheme.Verifier()

	message := pedersen.NewMessage(field.FromUint64(42))
	commitment, witness, err := committer.Commit(message, crand.Reader)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := verifier.Verify(commitment, message, witness)
		if err != nil {
			b.Fatal("verification failed")
		}
	}
}

func BenchmarkReRandomise(b *testing.B) {
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()
	h, err := curve.Hash([]byte("bench-h-rerandom"))
	require.NoError(b, err)

	key, err := pedersen.NewCommitmentKey(g, h)
	require.NoError(b, err)
	scheme, err := pedersen.NewScheme(key)
	require.NoError(b, err)
	committer := scheme.Committer()

	message := pedersen.NewMessage(field.FromUint64(42))
	commitment, _, err := committer.Commit(message, crand.Reader)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := commitment.ReRandomise(key, crand.Reader)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHomomorphicOps(b *testing.B) {
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()
	h, err := curve.Hash([]byte("bench-h-homo"))
	require.NoError(b, err)

	key, err := pedersen.NewCommitmentKey(g, h)
	require.NoError(b, err)
	scheme, err := pedersen.NewScheme(key)
	require.NoError(b, err)
	committer := scheme.Committer()

	m1 := pedersen.NewMessage(field.FromUint64(10))
	m2 := pedersen.NewMessage(field.FromUint64(20))
	c1, _, err := committer.Commit(m1, crand.Reader)
	require.NoError(b, err)
	c2, _, err := committer.Commit(m2, crand.Reader)
	require.NoError(b, err)

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = c1.Op(c2)
		}
	})

	b.Run("ScalarMul", func(b *testing.B) {
		scalar := pedersen.NewMessage(field.FromUint64(3))
		for i := 0; i < b.N; i++ {
			_ = c1.ScalarOp(scalar)
		}
	})
}
