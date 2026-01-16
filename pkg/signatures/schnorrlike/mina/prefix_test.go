package mina

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignaturePrefix(t *testing.T) {
	t.Parallel()

	t.Run("mainnet", func(t *testing.T) {
		prefix := SignaturePrefix(MainNet)
		assert.Equal(t, Prefix("MinaSignatureMainnet"), prefix)
		assert.Len(t, prefix, 20)
	})

	t.Run("testnet", func(t *testing.T) {
		prefix := SignaturePrefix(TestNet)
		assert.Equal(t, Prefix("CodaSignature*******"), prefix)
		assert.Len(t, prefix, 20)
	})

	t.Run("custom network", func(t *testing.T) {
		prefix := SignaturePrefix(NetworkId("custom"))
		// Should be "customSignature" padded to 20 chars
		assert.Len(t, prefix, 20)
		assert.Equal(t, Prefix("customSignature*****"), prefix)
	})

	t.Run("long custom network", func(t *testing.T) {
		prefix := SignaturePrefix(NetworkId("verylongnetworkname"))
		// Should be truncated to 20 chars
		assert.Len(t, prefix, 20)
		// "verylongnetworknameSignature" truncated to 20
		assert.Equal(t, Prefix("verylongnetworkname"), prefix[0:19])
	})
}

func TestPrefixToBaseFieldElement(t *testing.T) {
	t.Parallel()

	t.Run("mainnet prefix", func(t *testing.T) {
		prefix := SignaturePrefix(MainNet)
		fe, err := prefix.ToBaseFieldElement()
		require.NoError(t, err)
		assert.NotNil(t, fe)
		assert.False(t, fe.IsZero())
	})

	t.Run("testnet prefix", func(t *testing.T) {
		prefix := SignaturePrefix(TestNet)
		fe, err := prefix.ToBaseFieldElement()
		require.NoError(t, err)
		assert.NotNil(t, fe)
		assert.False(t, fe.IsZero())
	})

	t.Run("different networks produce different field elements", func(t *testing.T) {
		mainnetPrefix := SignaturePrefix(MainNet)
		testnetPrefix := SignaturePrefix(TestNet)

		mainnetFE, err := mainnetPrefix.ToBaseFieldElement()
		require.NoError(t, err)

		testnetFE, err := testnetPrefix.ToBaseFieldElement()
		require.NoError(t, err)

		assert.False(t, mainnetFE.Equal(testnetFE))
	})

	t.Run("prefix too long", func(t *testing.T) {
		// Create a prefix longer than field size (33 bytes > 32 bytes)
		prefix := Prefix(make([]byte, 33))
		fe, err := prefix.ToBaseFieldElement()
		assert.Nil(t, fe)
		assert.Error(t, err)
	})
}

func TestGetNetworkIdHashInput(t *testing.T) {
	t.Parallel()

	t.Run("mainnet", func(t *testing.T) {
		val, bits := getNetworkIdHashInput(MainNet)
		assert.Equal(t, uint64(1), val.Uint64())
		assert.Equal(t, 8, bits)
	})

	t.Run("testnet", func(t *testing.T) {
		val, bits := getNetworkIdHashInput(TestNet)
		assert.Equal(t, uint64(0), val.Uint64())
		assert.Equal(t, 8, bits)
	})

	t.Run("custom network", func(t *testing.T) {
		val, bits := getNetworkIdHashInput(NetworkId("test"))
		assert.NotNil(t, val)
		// Custom network string "test" -> 4 bytes * 8 bits = 32 bits
		assert.Equal(t, 32, bits)
	})
}

func TestCreateCustomPrefix(t *testing.T) {
	t.Parallel()

	t.Run("short input", func(t *testing.T) {
		prefix := createCustomPrefix("short")
		assert.Len(t, prefix, 20)
		assert.Equal(t, Prefix("short***************"), prefix)
	})

	t.Run("exact length input", func(t *testing.T) {
		prefix := createCustomPrefix("12345678901234567890")
		assert.Len(t, prefix, 20)
		assert.Equal(t, Prefix("12345678901234567890"), prefix)
	})

	t.Run("long input", func(t *testing.T) {
		prefix := createCustomPrefix("12345678901234567890EXTRA")
		assert.Len(t, prefix, 20)
		assert.Equal(t, Prefix("12345678901234567890"), prefix)
	})

	t.Run("empty input", func(t *testing.T) {
		prefix := createCustomPrefix("")
		assert.Len(t, prefix, 20)
		// All padding
		assert.Equal(t, Prefix("********************"), prefix)
	})
}

func TestNetworkIdOfString(t *testing.T) {
	t.Parallel()

	t.Run("single char", func(t *testing.T) {
		val, bits := networkIdOfString("a")
		assert.NotNil(t, val)
		assert.Equal(t, 8, bits)
	})

	t.Run("multiple chars", func(t *testing.T) {
		val, bits := networkIdOfString("test")
		assert.NotNil(t, val)
		assert.Equal(t, 32, bits) // 4 chars * 8 bits
	})

	t.Run("empty string", func(t *testing.T) {
		val, bits := networkIdOfString("")
		assert.NotNil(t, val)
		assert.Equal(t, 0, bits)
		assert.Equal(t, uint64(0), val.Uint64())
	})
}

func TestNumberToBytePadded(t *testing.T) {
	t.Parallel()

	t.Run("zero", func(t *testing.T) {
		result := numberToBytePadded(0)
		assert.Equal(t, "00000000", result)
	})

	t.Run("one", func(t *testing.T) {
		result := numberToBytePadded(1)
		assert.Equal(t, "00000001", result)
	})

	t.Run("255", func(t *testing.T) {
		result := numberToBytePadded(255)
		assert.Equal(t, "11111111", result)
	})

	t.Run("128", func(t *testing.T) {
		result := numberToBytePadded(128)
		assert.Equal(t, "10000000", result)
	})

	t.Run("'a' (97)", func(t *testing.T) {
		result := numberToBytePadded(97)
		assert.Equal(t, "01100001", result)
	})
}

func TestBytesToBits(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		bits := bytesToBits(nil)
		assert.Empty(t, bits)
	})

	t.Run("single byte zero", func(t *testing.T) {
		bits := bytesToBits([]byte{0})
		assert.Len(t, bits, 8)
		for i := range 8 {
			assert.False(t, bits[i])
		}
	})

	t.Run("single byte 0xFF", func(t *testing.T) {
		bits := bytesToBits([]byte{0xFF})
		assert.Len(t, bits, 8)
		for i := range 8 {
			assert.True(t, bits[i])
		}
	})

	t.Run("single byte 0x01", func(t *testing.T) {
		// 0x01 = 0b00000001, LSB-first should give [true, false, false, ...]
		bits := bytesToBits([]byte{0x01})
		assert.Len(t, bits, 8)
		assert.True(t, bits[0])
		for i := 1; i < 8; i++ {
			assert.False(t, bits[i])
		}
	})

	t.Run("multiple bytes", func(t *testing.T) {
		bits := bytesToBits([]byte{0x01, 0x02})
		assert.Len(t, bits, 16)
		// First byte 0x01: [true, false, false, false, false, false, false, false]
		assert.True(t, bits[0])
		// Second byte 0x02: [false, true, false, false, false, false, false, false]
		assert.False(t, bits[8])
		assert.True(t, bits[9])
	})
}

func TestReversedBytesPrefix(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		result := reversedBytes(nil)
		assert.Empty(t, result)
	})

	t.Run("single byte", func(t *testing.T) {
		result := reversedBytes([]byte{0x42})
		assert.Equal(t, []byte{0x42}, result)
	})

	t.Run("multiple bytes", func(t *testing.T) {
		result := reversedBytes([]byte{0x01, 0x02, 0x03})
		assert.Equal(t, []byte{0x03, 0x02, 0x01}, result)
	})
}
