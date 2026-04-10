package base58_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/base58"
)

var stringTests = []struct {
	in  string
	out base58.Base58
}{
	{"", ""},
	{" ", "Z"},
	{"-", "n"},
	{"0", "q"},
	{"1", "r"},
	{"-1", "4SU"},
	{"11", "4k8"},
	{"abc", "ZiCa"},
	{"1234598760", "3mJr7AoUXx2Wqd"},
	{"abcdefghijklmnopqrstuvwxyz", "3yxU3u1igY8WkgtjK92fbJQCd4BZiiT1v25f"},
	{"00000000000000000000000000000000000000000000000000000000000000", "3sN2THZeE9Eh9eYrwkvZqNstbHGvrxSAM7gXUXvyFQP8XvQLUqNCS27icwUeDT7ckHm4FUHM2mTVh1vbLmk7y"},
}

var invalidStringTests = []struct {
	in base58.Base58
}{
	{"0"},
	{"O"},
	{"I"},
	{"l"},
	{"3mJr0"},
	{"O3yxU"},
	{"3sNI"},
	{"4kl8"},
	{"0OIl"},
	{"!@#$%^&*()-_=+~`"},
}

var hexTests = []struct {
	in  string
	out base58.Base58
}{
	{"61", "2g"},
	{"626262", "a3gV"},
	{"636363", "aPEr"},
	{"73696d706c792061206c6f6e6720737472696e67", "2cFupjhnEsSn59qHXstmK2ffpLv2"},
	{"00eb15231dfceb60925886b67d065299925915aeb172c06647", "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"},
	{"516b6fcd0f", "ABnLTmg"},
	{"bf4f89001e670274dd", "3SEo3LWLoPntC"},
	{"572e4794", "3EFU7m"},
	{"ecac89cad93923c02321", "EJDM8drfXA6uyA"},
	{"10c8511e", "Rt5zm"},
	{"00000000000000000000", "1111111111"},
}

func TestBase58(t *testing.T) {
	t.Parallel()
	// Encode tests
	for i, test := range stringTests {
		t.Run(fmt.Sprintf("stringTest-%d", i), func(t *testing.T) {
			t.Parallel()
			actual := base58.Encode([]byte(test.in))
			require.Equal(t, test.out, actual)
		})
	}

	// Decode tests
	for i, test := range hexTests {
		t.Run(fmt.Sprintf("hexTest-%d", i), func(t *testing.T) {
			t.Parallel()
			actual, err := base58.Decode(test.out)
			require.NoError(t, err)
			expected, err := hex.DecodeString(test.in)
			require.NoError(t, err)
			require.Equal(t, expected, actual)
		})
	}

	// Encode/decode roundtrip tests
	for i, test := range hexTests {
		t.Run(fmt.Sprintf("roundtripHexTest-%d", i), func(t *testing.T) {
			t.Parallel()
			decoded, err := base58.Decode(test.out)
			require.NoError(t, err)
			require.Equal(t, test.out, base58.Encode(decoded))
		})
	}

	// Decode with invalid input
	for i, test := range invalidStringTests {
		t.Run(fmt.Sprintf("invalidStringTest-%d", i), func(t *testing.T) {
			t.Parallel()
			_, err := base58.Decode(test.in)
			require.ErrorIs(t, err, base58.ErrInvalidCharacter)
		})
	}
}

func TestEncodeNilMatchesEmpty(t *testing.T) {
	t.Parallel()

	require.Equal(t, base58.Base58(""), base58.Encode(nil))
	require.Equal(t, base58.Encode([]byte{}), base58.Encode(nil))
}

func TestBase58EqualDifferentLengths(t *testing.T) {
	t.Parallel()

	require.False(t, base58.Base58("1").Equal("12"))
}

func TestDecodeRoundtripEdgeCases(t *testing.T) {
	t.Parallel()

	testCases := [][]byte{
		nil,
		{},
		{0},
		{0, 0, 0},
		{0, 0, 1, 2, 3},
		{1, 2, 3, 0, 0},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("edge-%d", i), func(t *testing.T) {
			t.Parallel()

			encoded := base58.Encode(tc)
			decoded, err := base58.Decode(encoded)
			require.NoError(t, err)
			expected := []byte(tc)
			if tc == nil {
				expected = []byte{}
			}
			require.Equal(t, expected, decoded)
		})
	}
}
