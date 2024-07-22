package bls_test

import (
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	itu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls/testutils"
)

const dir = "./vectors"

type signVector struct {
	Input struct {
		PrivateKey itu.HexBytes `json:"privkey"`
		Message    itu.HexBytes `json:"message"`
	} `json:"input"`
	Output itu.HexBytes `json:"output"`
}

type verifyVector struct {
	Input struct {
		PublicKey itu.HexBytes `json:"pubkey"`
		Message   itu.HexBytes `json:"message"`
		Signature itu.HexBytes `json:"signature"`
	} `json:"input"`
	Output bool `json:"output"`
}

type aggregateVector struct {
	Input  []itu.HexBytes `json:"input"`
	Output itu.HexBytes   `json:"output"`
}

type aggregateVerifyVector struct {
	Input struct {
		PublicKeys []itu.HexBytes `json:"pubkeys"`
		Messages   []itu.HexBytes `json:"messages"`
		Signature  itu.HexBytes   `json:"signature"`
	} `json:"input"`
	Output bool `json:"output"`
}

type batchVerifyVector struct {
	Input struct {
		PublicKeys []itu.HexBytes `json:"pubkeys"`
		Messages   []itu.HexBytes `json:"messages"`
		Signatures []itu.HexBytes `json:"signatures"`
	} `json:"input"`
	Output bool `json:"output"`
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
			_, _, _, err := testutils.RoundTripWithKeysInG1(nil, message, boundedScheme)
			require.NoError(t, err)
		})

		t.Run("short signatures", func(t *testing.T) {
			t.Parallel()
			_, _, _, err := testutils.RoundTripWithKeysInG2(nil, message, boundedScheme)
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
				privateKey, signature, pop, err := testutils.RoundTripWithKeysInG1(nil, message, boundedScheme)
				require.NoError(t, err)
				err = bls.Verify(privateKey.PublicKey, signature, []byte("ETH > BTC"), pop, boundedScheme, nil)
				require.Error(t, err)
			})

			t.Run("short signatures", func(t *testing.T) {
				t.Parallel()
				privateKey, signature, pop, err := testutils.RoundTripWithKeysInG2(nil, message, boundedScheme)
				require.NoError(t, err)
				err = bls.Verify(privateKey.PublicKey, signature, []byte("ETH > BTC"), pop, boundedScheme, nil)
				require.Error(t, err)
			})
		})
		t.Run("random or identity signature", func(t *testing.T) {
			t.Parallel()
			t.Run("short keys", func(t *testing.T) {
				t.Parallel()
				privateKey, signature, pop, err := testutils.RoundTripWithKeysInG1(nil, message, boundedScheme)
				require.NoError(t, err)
				p, err := bls12381.NewG2().Random(prng)
				require.NoError(t, err)
				signature.Value, _ = p.(curves.PairingPoint)
				err = bls.Verify(privateKey.PublicKey, signature, message, pop, boundedScheme, nil)
				require.Error(t, err)
				signature.Value = bls12381.NewG2().AdditiveIdentity().(curves.PairingPoint)
				err = bls.Verify(privateKey.PublicKey, signature, message, pop, boundedScheme, nil)
				require.Error(t, err)
			})

			t.Run("short signatures", func(t *testing.T) {
				t.Parallel()
				privateKey, signature, pop, err := testutils.RoundTripWithKeysInG2(nil, message, boundedScheme)
				require.NoError(t, err)
				p, err := bls12381.NewG2().Random(prng)
				require.NoError(t, err)
				signature.Value, _ = p.(curves.PairingPoint)
				err = bls.Verify(privateKey.PublicKey, signature, message, pop, boundedScheme, nil)
				require.Error(t, err)
				signature.Value = bls12381.NewG2().AdditiveIdentity().(curves.PairingPoint)
				err = bls.Verify(privateKey.PublicKey, signature, message, pop, boundedScheme, nil)
				require.Error(t, err)
			})
		})
		t.Run("random or identity publicKey", func(t *testing.T) {
			t.Parallel()
			t.Run("short keys", func(t *testing.T) {
				t.Parallel()
				privateKey, signature, pop, err := testutils.RoundTripWithKeysInG1(nil, message, boundedScheme)
				require.NoError(t, err)
				p, err := bls12381.NewG2().Random(prng)
				require.NoError(t, err)
				privateKey.PublicKey.Y, _ = p.(curves.PairingPoint)
				err = bls.Verify(privateKey.PublicKey, signature, message, pop, boundedScheme, nil)
				require.Error(t, err)
				privateKey.PublicKey.Y = bls12381.NewG2().AdditiveIdentity().(curves.PairingPoint)
				err = bls.Verify(privateKey.PublicKey, signature, message, pop, boundedScheme, nil)
				require.Error(t, err)
			})

			t.Run("short signatures", func(t *testing.T) {
				t.Parallel()
				privateKey, signature, pop, err := testutils.RoundTripWithKeysInG2(nil, message, boundedScheme)
				require.NoError(t, err)
				p, err := bls12381.NewG2().Random(prng)
				require.NoError(t, err)
				privateKey.PublicKey.Y, _ = p.(curves.PairingPoint)
				err = bls.Verify(privateKey.PublicKey, signature, message, pop, boundedScheme, nil)
				require.Error(t, err)
				privateKey.PublicKey.Y = bls12381.NewG2().AdditiveIdentity().(curves.PairingPoint)
				err = bls.Verify(privateKey.PublicKey, signature, message, pop, boundedScheme, nil)
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
		for _, aggregationSize := range []int{2, 5, 10} {
			boundedScheme := scheme
			boundedAggregationSize := aggregationSize

			t.Run(fmt.Sprintf("short keys (RKP: %d, aggSize: %d)", boundedScheme, boundedAggregationSize), func(t *testing.T) {
				t.Parallel()
				publicKeys := make([]*bls.PublicKey[testutils.G1], boundedAggregationSize)
				signatures := make([]*bls.Signature[testutils.G2], boundedAggregationSize)
				pops := make([]*bls.ProofOfPossession[testutils.G2], boundedAggregationSize)
				messages := make([][]byte, boundedAggregationSize)

				for i := 0; i < boundedAggregationSize; i++ {
					m := message[:]
					if boundedScheme == bls.Basic {
						p, err := bls12381.NewG2().Random(crand.Reader)
						require.NoError(t, err)
						m = p.ToAffineCompressed()
					}
					privateKey, signature, pop, err := testutils.RoundTripWithKeysInG1(nil, m, boundedScheme)
					require.NoError(t, err)
					publicKeys[i] = privateKey.PublicKey
					signatures[i] = signature
					pops[i] = pop
					messages[i] = m
				}

				sigAg, err := bls.AggregateSignatures(signatures...)
				require.NoError(t, err)
				require.NotNil(t, sigAg)
				require.False(t, sigAg.Value.IsAdditiveIdentity())
				require.True(t, sigAg.Value.IsTorsionElementUnderAddition(bls12381.NewG2().Order()))

				if boundedScheme != bls.POP {
					pops = nil
				}

				err = bls.AggregateVerify(publicKeys, messages, sigAg, pops, boundedScheme, nil)
				require.NoError(t, err)

				if boundedScheme == bls.POP {
					err = bls.FastAggregateVerify(publicKeys, message, sigAg, pops)
					require.NoError(t, err)
				}
			})

			boundedScheme2 := scheme
			boundedAggregationSize2 := aggregationSize

			t.Run(fmt.Sprintf("short signatures (RKP: %d, aggSize: %d)", boundedScheme2, boundedAggregationSize2), func(t *testing.T) {
				t.Parallel()
				publicKeys := make([]*bls.PublicKey[testutils.G2], boundedAggregationSize2)
				signatures := make([]*bls.Signature[testutils.G1], boundedAggregationSize2)
				pops := make([]*bls.ProofOfPossession[testutils.G1], boundedAggregationSize2)
				messages := make([][]byte, boundedAggregationSize2)

				for i := 0; i < boundedAggregationSize2; i++ {
					m := message
					if boundedScheme2 == bls.Basic {
						p, err := bls12381.NewG2().Random(crand.Reader)
						require.NoError(t, err)
						m = p.ToAffineCompressed()
					}
					privateKey, signature, pop, err := testutils.RoundTripWithKeysInG2(nil, m, boundedScheme2)
					require.NoError(t, err)
					publicKeys[i] = privateKey.PublicKey
					signatures[i] = signature
					pops[i] = pop
					messages[i] = m
				}

				sigAg, err := bls.AggregateSignatures(signatures...)
				require.NoError(t, err)
				require.NotNil(t, sigAg)
				require.False(t, sigAg.Value.IsAdditiveIdentity())
				require.True(t, sigAg.Value.IsTorsionElementUnderAddition(bls12381.NewG1().SubGroupOrder()))

				if boundedScheme2 != bls.POP {
					pops = nil
				}

				err = bls.AggregateVerify(publicKeys, messages, sigAg, pops, boundedScheme2, nil)
				require.NoError(t, err)

				if boundedScheme2 == bls.POP {
					err = bls.FastAggregateVerify(publicKeys, message, sigAg, pops)
					require.NoError(t, err)
				}
			})

		}
	}
}

func TestCanVerifyBatchesOfAggregateSignatures(t *testing.T) {
	t.Parallel()
	var err error
	batchSize := 10
	signers := 5
	scheme := bls.Basic

	privateKeys := make([]*bls.PrivateKey[testutils.G1], signers)
	publicKeys := make([]*bls.PublicKey[testutils.G1], signers)
	schemes := make([]bls.RogueKeyPrevention, batchSize)
	for i := 0; i < signers; i++ {
		sk, err := testutils.KeygenInG1()
		require.NoError(t, err)

		privateKeys[i] = sk
		publicKeys[i] = sk.PublicKey
	}

	batchMessages := make([][][]byte, batchSize)
	aggregatedSignatures := make([]*bls.Signature[testutils.G2], batchSize)

	for i := 0; i < batchSize; i++ {
		batchMessages[i] = make([][]byte, signers)
		signatures := make([]*bls.Signature[testutils.G2], signers)
		for j := 0; j < signers; j++ {
			batchMessages[i][j] = []byte(fmt.Sprintf("%d_%d_%x", i, j, publicKeys[j].Y.ToAffineCompressed()))
			_, signatures[j], _, err = testutils.RoundTripWithKeysInG1(privateKeys[j], batchMessages[i][j], scheme)
			require.NoError(t, err)
		}
		aggregatedSignatures[i], err = bls.AggregateSignatures(signatures...)
		require.NoError(t, err)
		schemes[i] = scheme
	}

	err = bls.BatchAggregateVerify(publicKeys, batchMessages, aggregatedSignatures, nil, schemes, nil, crand.Reader)
	require.NoError(t, err)

}

func testSignVector(t *testing.T, v *signVector) {
	t.Helper()
	privateKey := &bls.PrivateKey[bls12381.G1]{}
	err := privateKey.UnmarshalBinary(v.Input.PrivateKey)
	// the test vectors only test whether the private key is zero or not
	if v.Output == nil {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
		signer, err := bls.NewSigner[bls12381.G1, bls12381.G2](privateKey, bls.Basic)
		require.NoError(t, err)

		signature, _, err := signer.Sign(v.Input.Message, []byte(bls.DstSignaturePopInG2))
		require.NoError(t, err)

		marshalled, err := signature.MarshalBinary()
		require.NoError(t, err)

		require.EqualValues(t, v.Output, marshalled)
	}
}

func TestSignVectors(t *testing.T) {
	t.Parallel()

	signDir := filepath.Join(dir, "sign")

	files, err := os.ReadDir(signDir)
	require.NoError(t, err)

	for _, file := range files {
		content, err := os.ReadFile(filepath.Join(signDir, file.Name()))
		require.NoError(t, err)

		var vector *signVector
		json.Unmarshal(content, &vector)

		t.Run(file.Name(), func(t *testing.T) {
			t.Parallel()
			testSignVector(t, vector)
		})
	}

}

func testVerifyVector(t *testing.T, v *verifyVector, name string) {
	t.Helper()
	publicKey := &bls.PublicKey[bls12381.G1]{}
	err := publicKey.UnmarshalBinary(v.Input.PublicKey)
	if !v.Output && strings.Contains(name, "infinity_pubkey") {
		require.Error(t, err)
	} else {
		signature := &bls.Signature[bls12381.G2]{}
		err := signature.UnmarshalBinary(v.Input.Signature)
		if !v.Output && strings.Contains(name, "signature") {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			err = bls.Verify(publicKey, signature, v.Input.Message, nil, bls.Basic, []byte(bls.DstSignaturePopInG2))
			if v.Output {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		}
	}
}

func TestVerifyVectors(t *testing.T) {
	t.Parallel()

	signDir := filepath.Join(dir, "verify")

	files, err := os.ReadDir(signDir)
	require.NoError(t, err)

	for _, file := range files {
		content, err := os.ReadFile(filepath.Join(signDir, file.Name()))
		require.NoError(t, err)

		var vector *verifyVector
		json.Unmarshal(content, &vector)

		boundedFileName := file.Name()

		t.Run(boundedFileName, func(t *testing.T) {
			t.Parallel()
			testVerifyVector(t, vector, boundedFileName)
		})
	}

}

func testAggregateVector(t *testing.T, v *aggregateVector, name string) {
	t.Helper()
	signatures := make([]*bls.Signature[bls12381.G2], len(v.Input))
	for i, value := range v.Input {
		signatures[i] = &bls.Signature[bls12381.G2]{}
		err := signatures[i].UnmarshalBinary(value)
		// we are deviating from the test vectors, because we don't allow infinity signatures to be aggregated in the first place.
		if strings.Contains(name, "infinity_signature") {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
	if !strings.Contains(name, "infinity_signature") {
		actualAggregated, err := bls.AggregateSignatures(signatures...)
		if len(v.Input) == 0 || v.Output == nil {
			require.Error(t, err)
		} else {
			actual, err := actualAggregated.MarshalBinary()
			require.NoError(t, err)
			require.EqualValues(t, v.Output, actual)
		}
	}
}

func TestAggregateVectors(t *testing.T) {
	t.Parallel()

	signDir := filepath.Join(dir, "aggregate")

	files, err := os.ReadDir(signDir)
	require.NoError(t, err)

	for _, file := range files {
		content, err := os.ReadFile(filepath.Join(signDir, file.Name()))
		require.NoError(t, err)

		var vector *aggregateVector
		json.Unmarshal(content, &vector)

		boundedFileName := file.Name()

		t.Run(boundedFileName, func(t *testing.T) {
			t.Parallel()
			testAggregateVector(t, vector, boundedFileName)
		})
	}

}

func testAggregateVerifyVector(t *testing.T, v *aggregateVerifyVector, name string) {
	t.Helper()
	aggregatedSignature := &bls.Signature[bls12381.G2]{}
	err := aggregatedSignature.UnmarshalBinary(v.Input.Signature)
	if strings.Contains(name, "signature") {
		require.Error(t, err)
		return
	}

	publicKeys := make([]*bls.PublicKey[bls12381.G1], len(v.Input.PublicKeys))
	foundError := false
	for i, value := range v.Input.PublicKeys {
		publicKeys[i] = &bls.PublicKey[bls12381.G1]{}
		err := publicKeys[i].UnmarshalBinary(value)
		if err != nil {
			foundError = true
		}
	}
	if strings.Contains(name, "infinity_pubkey") {
		require.True(t, foundError)
		return
	}
	require.False(t, foundError)
	messages := make([][]byte, len(v.Input.Messages))
	for i, m := range v.Input.Messages {
		messages[i] = []byte(m)
	}
	err = bls.AggregateVerify(publicKeys, messages, aggregatedSignature, nil, bls.Basic, []byte(bls.DstSignaturePopInG2))
	require.NoError(t, err)
}

func TestAggregateVerifyVectors(t *testing.T) {
	t.Parallel()

	signDir := filepath.Join(dir, "aggregate_verify")

	files, err := os.ReadDir(signDir)
	require.NoError(t, err)

	for _, file := range files {
		content, err := os.ReadFile(filepath.Join(signDir, file.Name()))
		require.NoError(t, err)

		var vector *aggregateVerifyVector
		json.Unmarshal(content, &vector)

		boundedFileName := file.Name()

		t.Run(boundedFileName, func(t *testing.T) {
			t.Parallel()
			testAggregateVerifyVector(t, vector, boundedFileName)
		})
	}

}

func testBatchVerifyVector(t *testing.T, v *batchVerifyVector, name string) {
	t.Helper()
	signatures := make([]*bls.Signature[bls12381.G2], len(v.Input.Signatures))
	foundError := false
	for i, value := range v.Input.Signatures {
		signatures[i] = &bls.Signature[bls12381.G2]{}
		err := signatures[i].UnmarshalBinary(value)
		if err != nil {
			foundError = true
		}
	}
	if strings.Contains(name, "infinity_signature") {
		require.True(t, foundError)
		return
	}
	require.False(t, foundError)

	publicKeys := make([]*bls.PublicKey[bls12381.G1], len(v.Input.PublicKeys))
	foundError = false
	for i, value := range v.Input.PublicKeys {
		publicKeys[i] = &bls.PublicKey[bls12381.G1]{}
		err := publicKeys[i].UnmarshalBinary(value)
		if err != nil {
			foundError = true
		}
	}
	require.False(t, foundError)
	messages := make([][]byte, len(v.Input.Messages))
	for i, m := range v.Input.Messages {
		messages[i] = []byte(m)
	}

	schemes := make([]bls.RogueKeyPrevention, len(signatures))
	tags := make([][]byte, len(signatures))
	for i := 0; i < len(signatures); i++ {
		schemes[i] = bls.Basic
		tags[i] = []byte(bls.DstSignaturePopInG2)
	}

	err := bls.BatchVerify(publicKeys, messages, signatures, nil, schemes, tags, crand.Reader)
	if strings.Contains(name, "invalid_forged_signature_set") {
		require.Error(t, err)
		require.True(t, errs.IsVerification(err))
	} else {
		require.NoError(t, err)
	}
}

func TestBatchVerifyVectors(t *testing.T) {
	t.Parallel()

	signDir := filepath.Join(dir, "batch_verify")

	files, err := os.ReadDir(signDir)
	require.NoError(t, err)

	for _, file := range files {
		content, err := os.ReadFile(filepath.Join(signDir, file.Name()))
		require.NoError(t, err)

		var vector *batchVerifyVector
		err = json.Unmarshal(content, &vector)
		require.NoError(t, err)

		boundedFileName := file.Name()

		t.Run(boundedFileName, func(t *testing.T) {
			t.Parallel()
			testBatchVerifyVector(t, vector, boundedFileName)
		})
	}
}
