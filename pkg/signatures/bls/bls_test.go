package bls_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/bls12381"
	"github.com/copperexchange/knox-primitives/pkg/signatures/bls"
)

type (
	G1 = *bls12381.PointG1
	G2 = *bls12381.PointG2
)

func keygenInG1(t *testing.T) *bls.PrivateKey[G1] {
	t.Helper()
	privateKey, err := bls.KeyGen[G1](crand.Reader)
	require.NoError(t, err)
	require.False(t, privateKey.D().IsZero())
	return privateKey
}

func keygenInG2(t *testing.T) *bls.PrivateKey[G2] {
	t.Helper()
	privateKey, err := bls.KeyGen[G2](crand.Reader)
	require.NoError(t, err)
	require.False(t, privateKey.D().IsZero())
	return privateKey
}

func roundTripWithKeysInG1(t *testing.T, message []byte, scheme bls.RogueKeyPrevention) (*bls.PrivateKey[G1], *bls.Signature[G2], *bls.ProofOfPossession[G2]) {
	t.Helper()
	privateKey := keygenInG1(t)
	signer, err := bls.NewSigner[G1, G2](privateKey, scheme)
	require.NoError(t, err)

	signature, pop, err := signer.Sign(message)
	require.NoError(t, err)
	if scheme == bls.POP {
		require.NotNil(t, pop)
		require.False(t, pop.Value.IsIdentity())
		require.True(t, pop.Value.IsTorsionFree())
		err = bls.PopVerify(privateKey.PublicKey, pop)
		require.NoError(t, err)
	} else {
		require.Nil(t, pop)
	}
	require.NotNil(t, signature)
	require.False(t, signature.Value.IsIdentity())
	require.True(t, signature.Value.IsTorsionFree())

	err = bls.Verify(privateKey.PublicKey, signature, message, pop, scheme)
	require.NoError(t, err)
	return privateKey, signature, pop
}

func roundTripWithKeysInG2(t *testing.T, message []byte, scheme bls.RogueKeyPrevention) (*bls.PrivateKey[G2], *bls.Signature[G1], *bls.ProofOfPossession[G1]) {
	t.Helper()
	privateKey := keygenInG2(t)
	signer, err := bls.NewSigner[G2, G1](privateKey, scheme)
	require.NoError(t, err)

	signature, pop, err := signer.Sign(message)
	require.NoError(t, err)
	if scheme == bls.POP {
		require.NotNil(t, pop)
		require.False(t, pop.Value.IsIdentity())
		require.True(t, pop.Value.IsTorsionFree())
		err = bls.PopVerify(privateKey.PublicKey, pop)
		require.NoError(t, err)
	} else {
		require.Nil(t, pop)
	}
	require.NotNil(t, signature)
	require.False(t, signature.Value.IsIdentity())
	require.True(t, signature.Value.IsTorsionFree())

	err = bls.Verify(privateKey.PublicKey, signature, message, pop, scheme)
	require.NoError(t, err)
	return privateKey, signature, pop
}

func TestCanSignAndVerify(t *testing.T) {
	t.Parallel()
	message := []byte("It is weird that BLS standard has no test vectors")

	for _, scheme := range []bls.RogueKeyPrevention{
		bls.Basic, bls.MessageAugmentation, bls.POP,
	} {
		boundedScheme := scheme
		t.Run("short keys", func(t *testing.T) {
			t.Parallel()
			roundTripWithKeysInG1(t, message, boundedScheme)
		})

		t.Run("short signatures", func(t *testing.T) {
			t.Parallel()
			roundTripWithKeysInG2(t, message, boundedScheme)
		})
	}
}

func TestCannotVerify(t *testing.T) {
	t.Parallel()
	prng := crand.Reader
	message := []byte("It is weird that BLS standard has no test vectors")

	for _, scheme := range []bls.RogueKeyPrevention{
		bls.Basic, bls.MessageAugmentation, bls.POP,
	} {
		boundedScheme := scheme
		t.Run("random message", func(t *testing.T) {
			t.Parallel()
			t.Run("short keys", func(t *testing.T) {
				t.Parallel()
				privateKey, signature, pop := roundTripWithKeysInG1(t, message, boundedScheme)
				err := bls.Verify(privateKey.PublicKey, signature, []byte("ETH > BTC"), pop, boundedScheme)
				require.Error(t, err)
			})

			t.Run("short signatures", func(t *testing.T) {
				t.Parallel()
				privateKey, signature, pop := roundTripWithKeysInG2(t, message, boundedScheme)
				err := bls.Verify(privateKey.PublicKey, signature, []byte("ETH > BTC"), pop, boundedScheme)
				require.Error(t, err)
			})
		})
		t.Run("random or identity signature", func(t *testing.T) {
			t.Parallel()
			t.Run("short keys", func(t *testing.T) {
				t.Parallel()
				privateKey, signature, pop := roundTripWithKeysInG1(t, message, boundedScheme)
				signature.Value = bls12381.NewG2().Point().Random(prng).(curves.PairingPoint)
				err := bls.Verify(privateKey.PublicKey, signature, message, pop, boundedScheme)
				require.Error(t, err)
				signature.Value = bls12381.NewG2().Point().Identity().(curves.PairingPoint)
				err = bls.Verify(privateKey.PublicKey, signature, message, pop, boundedScheme)
				require.Error(t, err)
			})

			t.Run("short signatures", func(t *testing.T) {
				t.Parallel()
				privateKey, signature, pop := roundTripWithKeysInG2(t, message, boundedScheme)
				signature.Value = bls12381.NewG1().Point().Random(prng).(curves.PairingPoint)
				err := bls.Verify(privateKey.PublicKey, signature, message, pop, boundedScheme)
				require.Error(t, err)
				signature.Value = bls12381.NewG1().Point().Identity().(curves.PairingPoint)
				err = bls.Verify(privateKey.PublicKey, signature, message, pop, boundedScheme)
				require.Error(t, err)
			})
		})
		t.Run("random or identity publicKey", func(t *testing.T) {
			t.Parallel()
			t.Run("short keys", func(t *testing.T) {
				t.Parallel()
				privateKey, signature, pop := roundTripWithKeysInG1(t, message, boundedScheme)
				privateKey.PublicKey.Y = bls12381.NewG1().Point().Random(prng).(curves.PairingPoint)
				err := bls.Verify(privateKey.PublicKey, signature, message, pop, boundedScheme)
				require.Error(t, err)
				privateKey.PublicKey.Y = bls12381.NewG1().Point().Identity().(curves.PairingPoint)
				err = bls.Verify(privateKey.PublicKey, signature, message, pop, boundedScheme)
				require.Error(t, err)
			})

			t.Run("short signatures", func(t *testing.T) {
				t.Parallel()
				privateKey, signature, pop := roundTripWithKeysInG2(t, message, boundedScheme)
				privateKey.PublicKey.Y = bls12381.NewG2().Point().Random(prng).(curves.PairingPoint)
				err := bls.Verify(privateKey.PublicKey, signature, message, pop, boundedScheme)
				require.Error(t, err)
				privateKey.PublicKey.Y = bls12381.NewG2().Point().Identity().(curves.PairingPoint)
				err = bls.Verify(privateKey.PublicKey, signature, message, pop, boundedScheme)
				require.Error(t, err)
			})
		})
	}
}

func TestCanSignAndVerifyInAggregate(t *testing.T) {
	t.Parallel()
	message := []byte("It is weird that BLS standard has no test vectors")

	for _, scheme := range []bls.RogueKeyPrevention{
		bls.Basic, bls.MessageAugmentation, bls.POP,
	} {
		for _, batchSize := range []int{2, 5, 10} {
			boundedScheme := scheme
			boundedBatchSize := batchSize

			t.Run("short keys", func(t *testing.T) {
				t.Parallel()
				publicKeys := make([]*bls.PublicKey[G1], boundedBatchSize)
				signatures := make([]*bls.Signature[G2], boundedBatchSize)
				pops := make([]*bls.ProofOfPossession[G2], boundedBatchSize)
				messages := make([][]byte, boundedBatchSize)

				for i := 0; i < boundedBatchSize; i++ {
					m := message
					if boundedScheme == bls.Basic {
						m = bls12381.NewG1().Point().Random(crand.Reader).ToAffineCompressed()
					}
					privateKey, signature, pop := roundTripWithKeysInG1(t, m, boundedScheme)
					publicKeys[i] = privateKey.PublicKey
					signatures[i] = signature
					pops[i] = pop
					messages[i] = m
				}

				sigAg, err := bls.AggregateSignatures(signatures...)
				require.NoError(t, err)
				require.NotNil(t, sigAg)
				require.False(t, sigAg.Value.IsIdentity())
				require.True(t, sigAg.Value.IsTorsionFree())

				if boundedScheme != bls.POP {
					pops = nil
				}

				err = bls.AggregateVerify(publicKeys, messages, sigAg, pops, boundedScheme)
				require.NoError(t, err)

				if boundedScheme == bls.POP {
					err = bls.FastAggregateVerify(publicKeys, message, sigAg, pops)
					require.NoError(t, err)
				}
			})

			t.Run("short signatures", func(t *testing.T) {
				t.Parallel()
				publicKeys := make([]*bls.PublicKey[G2], boundedBatchSize)
				signatures := make([]*bls.Signature[G1], boundedBatchSize)
				pops := make([]*bls.ProofOfPossession[G1], boundedBatchSize)
				messages := make([][]byte, boundedBatchSize)

				for i := 0; i < boundedBatchSize; i++ {
					m := message
					if boundedScheme == bls.Basic {
						m = bls12381.NewG2().Point().Random(crand.Reader).ToAffineCompressed()
					}
					privateKey, signature, pop := roundTripWithKeysInG2(t, m, boundedScheme)
					publicKeys[i] = privateKey.PublicKey
					signatures[i] = signature
					pops[i] = pop
					messages[i] = m
				}

				sigAg, err := bls.AggregateSignatures(signatures...)
				require.NoError(t, err)
				require.NotNil(t, sigAg)
				require.False(t, sigAg.Value.IsIdentity())
				require.True(t, sigAg.Value.IsTorsionFree())

				if boundedScheme != bls.POP {
					pops = nil
				}

				err = bls.AggregateVerify(publicKeys, messages, sigAg, pops, boundedScheme)
				require.NoError(t, err)

				if boundedScheme == bls.POP {
					err = bls.FastAggregateVerify(publicKeys, message, sigAg, pops)
					require.NoError(t, err)
				}
			})

		}
	}
}
