package indcpacom_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/commitments/indcpacom"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
)

// ─── Generic test suite ──────────────────────────────────────────────

type suite[
	PK encryption.PublicKey[PK],
	M encryption.Plaintext,
	C encryption.ReRandomisableCiphertext[C, N, PK],
	N interface {
		encryption.Nonce
		algebra.Operand[N]
	},
] struct {
	committer     *indcpacom.Committer[N, M, C, PK]
	verifier      *indcpacom.Verifier[N, M, C, PK]
	key           *indcpacom.Key[PK]
	sampleMessage func(testing.TB) *indcpacom.Message[M]
	sampleWitness func(testing.TB) *indcpacom.Witness[N]
	name          string
	encName       string
}

func runSuite[
	PK encryption.PublicKey[PK],
	M encryption.Plaintext,
	C encryption.ReRandomisableCiphertext[C, N, PK],
	N interface {
		encryption.Nonce
		algebra.Operand[N]
	},
](t *testing.T, s suite[PK, M, C, N]) {
	t.Helper()
	t.Run("basic commit and verify", func(t *testing.T) {
		t.Parallel()
		msg := s.sampleMessage(t)
		commitment, witness, err := s.committer.Commit(msg, pcg.NewRandomised())
		require.NoError(t, err)
		require.NotNil(t, commitment)
		require.NotNil(t, witness)

		err = s.verifier.Verify(commitment, msg, witness)
		require.NoError(t, err)
	})

	t.Run("commit with witness", func(t *testing.T) {
		t.Parallel()
		msg := s.sampleMessage(t)
		witness := s.sampleWitness(t)

		c1, err := s.committer.CommitWithWitness(msg, witness)
		require.NoError(t, err)
		c2, err := s.committer.CommitWithWitness(msg, witness)
		require.NoError(t, err)
		require.True(t, c1.Equal(c2), "deterministic commitment should match")

		err = s.verifier.Verify(c1, msg, witness)
		require.NoError(t, err)
		err = s.verifier.Verify(c2, msg, witness)
		require.NoError(t, err)
	})

	t.Run("wrong message fails", func(t *testing.T) {
		t.Parallel()
		msg1 := s.sampleMessage(t)
		msg2 := s.sampleMessage(t)

		commitment, witness, err := s.committer.Commit(msg1, pcg.NewRandomised())
		require.NoError(t, err)

		err = s.verifier.Verify(commitment, msg2, witness)
		require.Error(t, err, "verification should fail with wrong message")
	})

	t.Run("wrong witness fails", func(t *testing.T) {
		t.Parallel()
		msg := s.sampleMessage(t)

		c1, w1, err := s.committer.Commit(msg, pcg.NewRandomised())
		require.NoError(t, err)
		_, w2, err := s.committer.Commit(msg, pcg.NewRandomised())
		require.NoError(t, err)

		err = s.verifier.Verify(c1, msg, w2)
		require.Error(t, err, "verification should fail with wrong witness")

		err = s.verifier.Verify(c1, msg, w1)
		require.NoError(t, err)
	})

	t.Run("re-randomisation", func(t *testing.T) {
		t.Parallel()
		msg := s.sampleMessage(t)

		c1, w1, err := s.committer.Commit(msg, pcg.NewRandomised())
		require.NoError(t, err)

		c2, rw, err := c1.ReRandomise(s.key, pcg.NewRandomised())
		require.NoError(t, err)
		require.NotNil(t, c2)
		require.NotNil(t, rw)
		require.False(t, c1.Equal(c2), "re-randomised commitment should be different")

		err = s.verifier.Verify(c1, msg, w1)
		require.NoError(t, err)

		combined := w1.Op(rw)
		err = s.verifier.Verify(c2, msg, combined)
		require.NoError(t, err, "re-randomised commitment should verify with combined witness")
	})

	t.Run("re-randomisation with witness", func(t *testing.T) {
		t.Parallel()
		msg := s.sampleMessage(t)
		rw := s.sampleWitness(t)

		c1, _, err := s.committer.Commit(msg, pcg.NewRandomised())
		require.NoError(t, err)

		c2, err := c1.ReRandomiseWithWitness(s.key, rw)
		require.NoError(t, err)
		c3, err := c1.ReRandomiseWithWitness(s.key, rw)
		require.NoError(t, err)
		require.True(t, c2.Equal(c3), "deterministic re-randomisation should match")
	})

	t.Run("multiple re-randomisations", func(t *testing.T) {
		t.Parallel()
		msg := s.sampleMessage(t)

		c0, w0, err := s.committer.Commit(msg, pcg.NewRandomised())
		require.NoError(t, err)

		c1, rw1, err := c0.ReRandomise(s.key, pcg.NewRandomised())
		require.NoError(t, err)
		c2, rw2, err := c1.ReRandomise(s.key, pcg.NewRandomised())
		require.NoError(t, err)
		c3, rw3, err := c2.ReRandomise(s.key, pcg.NewRandomised())
		require.NoError(t, err)

		require.False(t, c0.Equal(c1))
		require.False(t, c1.Equal(c2))
		require.False(t, c2.Equal(c3))
		require.False(t, c0.Equal(c3))

		err = s.verifier.Verify(c0, msg, w0)
		require.NoError(t, err)

		w1 := w0.Op(rw1)
		err = s.verifier.Verify(c1, msg, w1)
		require.NoError(t, err)

		w2 := w1.Op(rw2)
		err = s.verifier.Verify(c2, msg, w2)
		require.NoError(t, err)

		w3 := w2.Op(rw3)
		err = s.verifier.Verify(c3, msg, w3)
		require.NoError(t, err)
	})

	t.Run("scheme name", func(t *testing.T) {
		t.Parallel()
		require.Contains(t, s.name, "IND-CPA-Com")
		require.Contains(t, s.name, s.encName)
	})

	t.Run("commitment equality", func(t *testing.T) {
		t.Parallel()
		msg := s.sampleMessage(t)

		c1, w1, err := s.committer.Commit(msg, pcg.NewRandomised())
		require.NoError(t, err)
		require.True(t, c1.Equal(c1))

		c2, err := s.committer.CommitWithWitness(msg, w1)
		require.NoError(t, err)
		require.True(t, c1.Equal(c2))

		c3, _, err := s.committer.Commit(msg, pcg.NewRandomised())
		require.NoError(t, err)
		require.False(t, c1.Equal(c3))
	})

	t.Run("value accessors", func(t *testing.T) {
		t.Parallel()
		msg := s.sampleMessage(t)
		require.NotNil(t, msg.Value())
		require.NotNil(t, s.key.Value())

		c, _, err := s.committer.Commit(msg, pcg.NewRandomised())
		require.NoError(t, err)
		require.NotNil(t, c.Value())

		w := s.sampleWitness(t)
		require.NotNil(t, w.Value())
	})

	t.Run("witness op", func(t *testing.T) {
		t.Parallel()
		msg := s.sampleMessage(t)
		w1 := s.sampleWitness(t)
		w2 := s.sampleWitness(t)

		// Commit with w1, re-randomise with w2. The combined witness w1 ⊕ w2
		// must verify the re-randomised commitment.
		c1, err := s.committer.CommitWithWitness(msg, w1)
		require.NoError(t, err)
		c2, err := c1.ReRandomiseWithWitness(s.key, w2)
		require.NoError(t, err)

		combined := w1.Op(w2)
		require.NotNil(t, combined)
		err = s.verifier.Verify(c2, msg, combined)
		require.NoError(t, err)
	})

	t.Run("nil inputs", func(t *testing.T) {
		t.Parallel()
		msg := s.sampleMessage(t)
		w := s.sampleWitness(t)

		t.Run("commit nil message", func(t *testing.T) {
			t.Parallel()
			_, _, err := s.committer.Commit(nil, pcg.NewRandomised())
			require.Error(t, err)
		})
		t.Run("commit nil prng", func(t *testing.T) {
			t.Parallel()
			_, _, err := s.committer.Commit(msg, nil)
			require.Error(t, err)
		})
		t.Run("commit with witness nil message", func(t *testing.T) {
			t.Parallel()
			_, err := s.committer.CommitWithWitness(nil, w)
			require.Error(t, err)
		})
		t.Run("commit with witness nil witness", func(t *testing.T) {
			t.Parallel()
			_, err := s.committer.CommitWithWitness(msg, nil)
			require.Error(t, err)
		})
		t.Run("new message nil", func(t *testing.T) {
			t.Parallel()
			var zeroM M
			_, err := indcpacom.NewMessage(zeroM)
			require.Error(t, err)
		})
		t.Run("new key nil", func(t *testing.T) {
			t.Parallel()
			var zeroPK PK
			_, err := indcpacom.NewKey(zeroPK)
			require.Error(t, err)
		})
		t.Run("new witness nil", func(t *testing.T) {
			t.Parallel()
			var zeroN N
			_, err := indcpacom.NewWitness(zeroN)
			require.Error(t, err)
		})
	})

	t.Run("re-randomise nil inputs", func(t *testing.T) {
		t.Parallel()
		msg := s.sampleMessage(t)
		commitment, witness, err := s.committer.Commit(msg, pcg.NewRandomised())
		require.NoError(t, err)

		t.Run("nil key", func(t *testing.T) {
			t.Parallel()
			_, _, err := commitment.ReRandomise(nil, pcg.NewRandomised())
			require.Error(t, err)
		})
		t.Run("nil prng", func(t *testing.T) {
			t.Parallel()
			_, _, err := commitment.ReRandomise(s.key, nil)
			require.Error(t, err)
		})
		t.Run("nil key with witness", func(t *testing.T) {
			t.Parallel()
			_, err := commitment.ReRandomiseWithWitness(nil, witness)
			require.Error(t, err)
		})
		t.Run("nil witness", func(t *testing.T) {
			t.Parallel()
			_, err := commitment.ReRandomiseWithWitness(s.key, nil)
			require.Error(t, err)
		})
		t.Run("nil receiver", func(t *testing.T) {
			t.Parallel()
			var nilC *indcpacom.Commitment[C, N, PK]
			_, _, err := nilC.ReRandomise(s.key, pcg.NewRandomised())
			require.Error(t, err)
		})
		t.Run("nil receiver with witness", func(t *testing.T) {
			t.Parallel()
			var nilC *indcpacom.Commitment[C, N, PK]
			_, err := nilC.ReRandomiseWithWitness(s.key, witness)
			require.Error(t, err)
		})
	})
}

// ─── Paillier ────────────────────────────────────────────────────────

func setupPaillier(tb testing.TB) suite[
	*paillier.PublicKey, *paillier.Plaintext,
	*paillier.Ciphertext, *paillier.Nonce,
] {
	tb.Helper()
	paillierScheme := paillier.NewScheme()
	kg, err := paillierScheme.Keygen()
	require.NoError(tb, err)
	_, pk, err := kg.Generate(pcg.NewRandomised())
	require.NoError(tb, err)

	key, err := indcpacom.NewKey(pk)
	require.NoError(tb, err)
	scheme, err := indcpacom.NewScheme(paillierScheme, key)
	require.NoError(tb, err)

	committer, err := scheme.Committer()
	require.NoError(tb, err)
	verifier, err := scheme.Verifier()
	require.NoError(tb, err)

	return suite[*paillier.PublicKey, *paillier.Plaintext, *paillier.Ciphertext, *paillier.Nonce]{
		committer: committer,
		verifier:  verifier,
		key:       key,
		name:      string(scheme.Name()),
		encName:   "paillier",
		sampleMessage: func(tb testing.TB) *indcpacom.Message[*paillier.Plaintext] {
			tb.Helper()
			pt, err := pk.PlaintextSpace().Sample(nil, nil, pcg.NewRandomised())
			require.NoError(tb, err)
			msg, err := indcpacom.NewMessage(pt)
			require.NoError(tb, err)
			return msg
		},
		sampleWitness: func(tb testing.TB) *indcpacom.Witness[*paillier.Nonce] {
			tb.Helper()
			nonce, err := pk.NonceSpace().Sample(pcg.NewRandomised())
			require.NoError(tb, err)
			w, err := indcpacom.NewWitness(nonce)
			require.NoError(tb, err)
			return w
		},
	}
}

func TestPaillier(t *testing.T) {
	t.Parallel()
	runSuite(t, setupPaillier(t))
}

// ─── ElGamal ─────────────────────────────────────────────────────────

type (
	egPoint  = *k256.Point
	egScalar = *k256.Scalar
	egPK     = *elgamal.PublicKey[egPoint, egScalar]
	egPT     = *elgamal.Plaintext[egPoint, egScalar]
	egCT     = *elgamal.Ciphertext[egPoint, egScalar]
	egNonce  = *elgamal.Nonce[egScalar]
)

func setupElGamal(tb testing.TB) suite[egPK, egPT, egCT, egNonce] {
	tb.Helper()
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	egScheme, err := elgamal.NewScheme(curve, field)
	require.NoError(tb, err)
	kg, err := egScheme.Keygen()
	require.NoError(tb, err)
	_, pk, err := kg.Generate(pcg.NewRandomised())
	require.NoError(tb, err)

	key, err := indcpacom.NewKey(pk)
	require.NoError(tb, err)
	scheme, err := indcpacom.NewScheme(egScheme, key)
	require.NoError(tb, err)

	committer, err := scheme.Committer()
	require.NoError(tb, err)
	verifier, err := scheme.Verifier()
	require.NoError(tb, err)

	return suite[egPK, egPT, egCT, egNonce]{
		committer: committer,
		verifier:  verifier,
		key:       key,
		name:      string(scheme.Name()),
		encName:   "elgamal",
		sampleMessage: func(tb testing.TB) *indcpacom.Message[egPT] {
			tb.Helper()
			p, err := curve.Random(pcg.NewRandomised())
			require.NoError(tb, err)
			pt, err := elgamal.NewPlaintext(p)
			require.NoError(tb, err)
			msg, err := indcpacom.NewMessage(pt)
			require.NoError(tb, err)
			return msg
		},
		sampleWitness: func(tb testing.TB) *indcpacom.Witness[egNonce] {
			tb.Helper()
			nv, err := algebrautils.RandomNonIdentity(field, pcg.NewRandomised())
			require.NoError(tb, err)
			nonce, err := elgamal.NewNonce(nv)
			require.NoError(tb, err)
			w, err := indcpacom.NewWitness(nonce)
			require.NoError(tb, err)
			return w
		},
	}
}

func TestElGamal(t *testing.T) {
	t.Parallel()
	runSuite(t, setupElGamal(t))
}
