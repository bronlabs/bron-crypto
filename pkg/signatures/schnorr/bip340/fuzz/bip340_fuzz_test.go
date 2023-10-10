package fuzz

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/bip340"
)

func Fuzz_Test(f *testing.F) {
	f.Add([]byte{0x00}, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, []byte{0x00}, int64(0))
	f.Fuzz(func(t *testing.T, s []byte, aux []byte, msg []byte, randomSeed int64) {
		prng := rand.New(rand.NewSource(randomSeed))
		secret, err := k256.New().Scalar().SetBytes(s)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip(err.Error())
		}
		require.NoError(t, err)
		privateKey, err := bip340.NewPrivateKey(secret)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		signer := bip340.NewSigner(privateKey)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		require.NotNil(t, signer)

		signature, err := signer.Sign(msg, aux, prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip(err.Error())
		}
		require.NoError(t, err)

		err = bip340.Verify(&privateKey.PublicKey, signature, msg)
		require.NoError(t, err)

		err = bip340.VerifyBatch([]*bip340.PublicKey{&privateKey.PublicKey}, []*bip340.Signature{signature}, [][]byte{
			msg,
		}, prng)
		require.NoError(t, err)
	})
}
