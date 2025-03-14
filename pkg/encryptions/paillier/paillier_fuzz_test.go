package paillier_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/encryptions/paillier"
)

func Fuzz_Test_encryptDecrypt(f *testing.F) {
	f.Add([]byte("hello world"))
	f.Fuzz(func(t *testing.T, message []byte) {
		// ignore message that is longer than 256 bits
		if len(message) > 32 {
			t.Skip()
		}
		hexMessage := strings.ToUpper(hex.EncodeToString(message))
		mappedMessage, err := new(saferith.Nat).SetHex(hexMessage)
		require.NoError(t, err)
		pub, sec, err := paillier.KeyGen(256, crand.Reader)
		require.NoError(t, err)

		// Ignoring the random value that was generated internally by `Encrypt`.
		cipher, _, err := pub.Encrypt(mappedMessage, crand.Reader)
		require.NoError(t, err)

		// Now decrypt using the secret key.
		decryptor, err := paillier.NewDecryptor(sec)
		require.NoError(t, err)
		_, err = decryptor.Decrypt(cipher)
		require.NoError(t, err)
	})
}

func Fuzz_Test_homomorphicAddition(f *testing.F) {
	f.Add(uint64(123), uint64(234))
	f.Fuzz(func(t *testing.T, m1 uint64, m2 uint64) {
		pub, sec, err := paillier.KeyGen(256, crand.Reader)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		msg1 := new(saferith.Nat).SetBig(new(big.Int).SetUint64(m1), new(big.Int).SetUint64(m1).BitLen())
		msg2 := new(saferith.Nat).SetBig(new(big.Int).SetUint64(m2), new(big.Int).SetUint64(m2).BitLen())

		cipher1, _, err := pub.Encrypt(msg1, crand.Reader)
		require.NoError(t, err)
		cipher2, _, err := pub.Encrypt(msg2, crand.Reader)
		require.NoError(t, err)

		fmt.Println("Adding their encrypted versions together.")
		cipher3, err := pub.Add(cipher1, cipher2)
		require.NoError(t, err)
		decryptor, err := paillier.NewDecryptor(sec)
		require.NoError(t, err)
		_, err = decryptor.Decrypt(cipher3)
		require.NoError(t, err)
	})
}

func Fuzz_Test_homomorphicMul(f *testing.F) {
	f.Add(uint64(123), uint64(234))
	f.Fuzz(func(t *testing.T, m1 uint64, m2 uint64) {
		pub, sec, err := paillier.KeyGen(256, crand.Reader)
		require.NoError(t, err)
		msg1 := new(saferith.Nat).SetBig(new(big.Int).SetUint64(m1), new(big.Int).SetUint64(m1).BitLen())
		msg2 := new(saferith.Nat).SetBig(new(big.Int).SetUint64(m2), new(big.Int).SetUint64(m2).BitLen())

		cipher2, _, err := pub.Encrypt(msg2, crand.Reader)
		require.NoError(t, err)

		fmt.Println("Adding their encrypted versions together.")
		cipher3, err := pub.MulPlaintext(cipher2, msg1)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		decryptor, err := paillier.NewDecryptor(sec)
		require.NoError(t, err)
		_, err = decryptor.Decrypt(cipher3)
		require.NoError(t, err)
	})
}
