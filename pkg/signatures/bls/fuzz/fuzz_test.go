package fuzz

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls/testutils"
)

type (
	G1 = *bls12381.PointG1
	G2 = *bls12381.PointG2
)

var schemes = []bls.RogueKeyPrevention{
	bls.Basic, bls.MessageAugmentation, bls.POP,
}

func Fuzz_Test_Keygen(f *testing.F) {
	f.Add(make([]byte, 32))
	f.Fuzz(func(t *testing.T, ikm []byte) {
		privateKey, err := bls.KeyGenWithSeed[G1](ikm)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip(err.Error())
		}
		require.NoError(t, err)
		require.False(t, privateKey.D().IsZero())
	})
}

func Fuzz_Test_Verify(f *testing.F) {
	f.Add(uint(0), []byte("message"))
	f.Add(uint(1), []byte("message"))
	f.Add(uint(2), []byte("message"))
	f.Fuzz(func(t *testing.T, schemeIndex uint, message []byte) {
		scheme := schemes[schemeIndex%uint(len(schemes))]
		privateKey, err := bls.KeyGen[G1](crand.Reader)
		require.NoError(t, err)
		require.False(t, privateKey.D().IsZero())
		signer, err := bls.NewSigner[G1, G2](privateKey, scheme)
		require.NoError(t, err)

		signature, pop, err := signer.Sign(message)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip(err.Error())
		}
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
	})
}

func Fuzz_Test_VerifyInAggregate(f *testing.F) {
	f.Add(uint(0), []byte("message"), uint(2))
	f.Add(uint(1), []byte("message"), uint(5))
	f.Add(uint(2), []byte("message"), uint(10))
	f.Fuzz(func(t *testing.T, schemeIndex uint, message []byte, boundedBatchSize uint) {
		boundedScheme := schemes[schemeIndex%uint(len(schemes))]
		boundedBatchSize = boundedBatchSize % uint(10)

		publicKeys := make([]*bls.PublicKey[G1], boundedBatchSize)
		signatures := make([]*bls.Signature[G2], boundedBatchSize)
		pops := make([]*bls.ProofOfPossession[G2], boundedBatchSize)
		messages := make([][]byte, boundedBatchSize)

		for i := 0; i < int(boundedBatchSize); i++ {
			m := message
			if boundedScheme == bls.Basic {
				m = bls12381.NewG1().Point().Random(crand.Reader).ToAffineCompressed()
			}
			privateKey, signature, pop, err := testutils.RoundTripWithKeysInG1(m, boundedScheme)
			if err != nil && !errs.IsKnownError(err) {
				require.NoError(t, err)
			}
			if err != nil {
				t.Skip(err.Error())
			}
			publicKeys[i] = privateKey.PublicKey
			signatures[i] = signature
			pops[i] = pop
			messages[i] = m
		}

		sigAg, err := bls.AggregateSignatures(signatures...)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip(err.Error())
		}
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
			if err != nil && !errs.IsKnownError(err) {
				require.NoError(t, err)
			}
			if err != nil {
				t.Skip(err.Error())
			}
			require.NoError(t, err)
		}
	})
}
