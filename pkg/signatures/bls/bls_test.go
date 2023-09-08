package bls_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton/pkg/base/curves"
	"github.com/copperexchange/krypton/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton/pkg/signatures/bls"
	"github.com/copperexchange/krypton/pkg/signatures/bls/testutils"
)

func TestCanSignAndVerify(t *testing.T) {
	t.Parallel()
	message := []byte("It is weird that BLS standard has no test vectors")

	for _, scheme := range []bls.RogueKeyPrevention{
		bls.Basic, bls.MessageAugmentation, bls.POP,
	} {
		boundedScheme := scheme
		t.Run("short keys", func(t *testing.T) {
			t.Parallel()
			_, _, _, err := testutils.RoundTripWithKeysInG1(message, boundedScheme)
			require.NoError(t, err)
		})

		t.Run("short signatures", func(t *testing.T) {
			t.Parallel()
			_, _, _, err := testutils.RoundTripWithKeysInG2(message, boundedScheme)
			require.NoError(t, err)
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
				privateKey, signature, pop, err := testutils.RoundTripWithKeysInG1(message, boundedScheme)
				require.NoError(t, err)
				err = bls.Verify(privateKey.PublicKey, signature, []byte("ETH > BTC"), pop, boundedScheme)
				require.Error(t, err)
			})

			t.Run("short signatures", func(t *testing.T) {
				t.Parallel()
				privateKey, signature, pop, err := testutils.RoundTripWithKeysInG2(message, boundedScheme)
				require.NoError(t, err)
				err = bls.Verify(privateKey.PublicKey, signature, []byte("ETH > BTC"), pop, boundedScheme)
				require.Error(t, err)
			})
		})
		t.Run("random or identity signature", func(t *testing.T) {
			t.Parallel()
			t.Run("short keys", func(t *testing.T) {
				t.Parallel()
				privateKey, signature, pop, err := testutils.RoundTripWithKeysInG1(message, boundedScheme)
				require.NoError(t, err)
				signature.Value = bls12381.NewG2().Point().Random(prng).(curves.PairingPoint)
				err = bls.Verify(privateKey.PublicKey, signature, message, pop, boundedScheme)
				require.Error(t, err)
				signature.Value = bls12381.NewG2().Point().Identity().(curves.PairingPoint)
				err = bls.Verify(privateKey.PublicKey, signature, message, pop, boundedScheme)
				require.Error(t, err)
			})

			t.Run("short signatures", func(t *testing.T) {
				t.Parallel()
				privateKey, signature, pop, err := testutils.RoundTripWithKeysInG2(message, boundedScheme)
				require.NoError(t, err)
				signature.Value = bls12381.NewG1().Point().Random(prng).(curves.PairingPoint)
				err = bls.Verify(privateKey.PublicKey, signature, message, pop, boundedScheme)
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
				privateKey, signature, pop, err := testutils.RoundTripWithKeysInG1(message, boundedScheme)
				require.NoError(t, err)
				privateKey.PublicKey.Y = bls12381.NewG1().Point().Random(prng).(curves.PairingPoint)
				err = bls.Verify(privateKey.PublicKey, signature, message, pop, boundedScheme)
				require.Error(t, err)
				privateKey.PublicKey.Y = bls12381.NewG1().Point().Identity().(curves.PairingPoint)
				err = bls.Verify(privateKey.PublicKey, signature, message, pop, boundedScheme)
				require.Error(t, err)
			})

			t.Run("short signatures", func(t *testing.T) {
				t.Parallel()
				privateKey, signature, pop, err := testutils.RoundTripWithKeysInG2(message, boundedScheme)
				require.NoError(t, err)
				privateKey.PublicKey.Y = bls12381.NewG2().Point().Random(prng).(curves.PairingPoint)
				err = bls.Verify(privateKey.PublicKey, signature, message, pop, boundedScheme)
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
				publicKeys := make([]*bls.PublicKey[testutils.G1], boundedBatchSize)
				signatures := make([]*bls.Signature[testutils.G2], boundedBatchSize)
				pops := make([]*bls.ProofOfPossession[testutils.G2], boundedBatchSize)
				messages := make([][]byte, boundedBatchSize)

				for i := 0; i < boundedBatchSize; i++ {
					m := message
					if boundedScheme == bls.Basic {
						m = bls12381.NewG1().Point().Random(crand.Reader).ToAffineCompressed()
					}
					privateKey, signature, pop, err := testutils.RoundTripWithKeysInG1(m, boundedScheme)
					require.NoError(t, err)
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
				publicKeys := make([]*bls.PublicKey[testutils.G2], boundedBatchSize)
				signatures := make([]*bls.Signature[testutils.G1], boundedBatchSize)
				pops := make([]*bls.ProofOfPossession[testutils.G1], boundedBatchSize)
				messages := make([][]byte, boundedBatchSize)

				for i := 0; i < boundedBatchSize; i++ {
					m := message
					if boundedScheme == bls.Basic {
						m = bls12381.NewG2().Point().Random(crand.Reader).ToAffineCompressed()
					}
					privateKey, signature, pop, err := testutils.RoundTripWithKeysInG2(m, boundedScheme)
					require.NoError(t, err)
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
