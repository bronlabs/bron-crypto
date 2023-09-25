package fuzz

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
)

func Fuzz_Test_encryptDecrypt(f *testing.F) {
	f.Add([]byte("hello world"))
	f.Fuzz(func(t *testing.T, message []byte) {
		hexMessage := strings.ToUpper(hex.EncodeToString(message))
		mappedMessage, err := new(saferith.Nat).SetHex(hexMessage)
		require.NoError(t, err)
		pub, sec, err := paillier.NewKeys(256)
		require.NoError(t, err)

		// Ignoring the random value that was generated internally by `Encrypt`.
		cipher, _, err := pub.Encrypt(mappedMessage)
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
		pub, sec, err := paillier.NewKeys(256)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		msg1 := new(saferith.Nat).SetBig(new(big.Int).SetUint64(m1), new(big.Int).SetUint64(m1).BitLen())
		msg2 := new(saferith.Nat).SetBig(new(big.Int).SetUint64(m2), new(big.Int).SetUint64(m2).BitLen())

		cipher1, _, err := pub.Encrypt(msg1)
		require.NoError(t, err)
		cipher2, _, err := pub.Encrypt(msg2)
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
		pub, sec, err := paillier.NewKeys(256)
		require.NoError(t, err)
		msg1 := new(saferith.Nat).SetBig(new(big.Int).SetUint64(m1), new(big.Int).SetUint64(m1).BitLen())
		msg2 := new(saferith.Nat).SetBig(new(big.Int).SetUint64(m2), new(big.Int).SetUint64(m2).BitLen())

		cipher2, _, err := pub.Encrypt(msg2)
		require.NoError(t, err)

		fmt.Println("Adding their encrypted versions together.")
		cipher3, err := pub.Mul(msg1, cipher2)
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
