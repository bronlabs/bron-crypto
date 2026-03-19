// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package base58_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/base58"
)

var checkEncodingStringTests = []struct {
	version base58.VersionPrefix
	in      base58.Base58
	out     base58.Base58
}{
	{20, "", "3MNQE1X"},
	{20, " ", "B2Kr6dBE"},
	{20, "-", "B3jv1Aft"},
	{20, "0", "B482yuaX"},
	{20, "1", "B4CmeGAC"},
	{20, "-1", "mM7eUf6kB"},
	{20, "11", "mP7BMTDVH"},
	{20, "abc", "4QiVtDjUdeq"},
	{20, "1234598760", "ZmNb8uQn5zvnUohNCEPP"},
	{20, "abcdefghijklmnopqrstuvwxyz", "K2RYDcKfupxwXdWhSAxQPCeiULntKm63UXyx5MvEH2"},
	{20, "00000000000000000000000000000000000000000000000000000000000000", "bi1EWXwJay2udZVxLJozuTb8Meg4W9c6xnmJaRDjg6pri5MBAxb9XwrpQXbtnqEoRV5U2pixnFfwyXC8tRAVC8XxnjK"},
}

func TestBase58Check(t *testing.T) {
	t.Parallel()
	for i, test := range checkEncodingStringTests {
		t.Run(fmt.Sprintf("CheckEncode-%d", i), func(t *testing.T) {
			// test encoding
			t.Parallel()
			actualEncoded := base58.CheckEncode([]byte(test.in), test.version)
			require.Equal(t, test.out, actualEncoded)

			// test decoding
			actualDecoded, actualDecodedVersion, err := base58.CheckDecode(actualEncoded)
			require.NoError(t, err)
			require.Equal(t, test.version, actualDecodedVersion)
			require.Equal(t, []byte(test.in), actualDecoded)
		})
	}

	// test the three decoding failure cases
	t.Run("invalid character", func(t *testing.T) {
		t.Parallel()
		_, _, err := base58.CheckDecode("0OIl")
		require.ErrorIs(t, err, base58.ErrInvalidCharacter)
	})

	t.Run("checksum error", func(t *testing.T) {
		t.Parallel()
		_, _, err := base58.CheckDecode("3MNQE1Y")
		require.ErrorIs(t, err, base58.ErrChecksumMismatch)
	})

	t.Run("decoded payloads shorter than version+checksum are rejected", func(t *testing.T) {
		t.Parallel()
		// Encode raw byte slices of length 0..4 (all shorter than minimumDecodedLength=5)
		// directly into base58, then verify CheckDecode rejects them.
		for length := range 5 {
			input := make([]byte, length)
			encoded := base58.Encode(input)
			_, _, err := base58.CheckDecode(encoded)
			require.ErrorIs(t, err, base58.ErrInvalidLength)
		}
	})
}
