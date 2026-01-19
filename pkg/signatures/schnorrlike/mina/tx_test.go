package mina //nolint:testpackage // to test unexported identifiers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLegacyTokenId(t *testing.T) {
	t.Parallel()

	bits := legacyTokenId()
	assert.Len(t, bits, 64)
	// First bit should be true, rest should be false
	assert.True(t, bits[0])
	for i := 1; i < 64; i++ {
		assert.False(t, bits[i], "bit %d should be false", i)
	}
}

func TestUint64ToBits(t *testing.T) {
	t.Parallel()

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		bits := uint64ToBits(0)
		assert.Len(t, bits, 64)
		for i := range 64 {
			assert.False(t, bits[i], "bit %d should be false for 0", i)
		}
	})

	t.Run("one", func(t *testing.T) {
		t.Parallel()
		bits := uint64ToBits(1)
		assert.Len(t, bits, 64)
		assert.True(t, bits[0], "bit 0 should be true for 1")
		for i := 1; i < 64; i++ {
			assert.False(t, bits[i], "bit %d should be false for 1", i)
		}
	})

	t.Run("max uint64", func(t *testing.T) {
		t.Parallel()
		bits := uint64ToBits(^uint64(0))
		assert.Len(t, bits, 64)
		for i := range 64 {
			assert.True(t, bits[i], "bit %d should be true for max", i)
		}
	})

	t.Run("specific value", func(t *testing.T) {
		t.Parallel()
		// 100000000 in binary (fee from test vector)
		bits := uint64ToBits(100000000)
		assert.Len(t, bits, 64)
		// Verify LSB-first encoding is correct
		// Reconstruct the value
		var result uint64
		for i := range 64 {
			if bits[i] {
				result |= 1 << i
			}
		}
		assert.Equal(t, uint64(100000000), result)
	})
}

func TestUint32ToBits(t *testing.T) {
	t.Parallel()

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		bits := uint32ToBits(0)
		assert.Len(t, bits, 32)
		for i := range 32 {
			assert.False(t, bits[i], "bit %d should be false for 0", i)
		}
	})

	t.Run("one", func(t *testing.T) {
		t.Parallel()
		bits := uint32ToBits(1)
		assert.Len(t, bits, 32)
		assert.True(t, bits[0], "bit 0 should be true for 1")
		for i := 1; i < 32; i++ {
			assert.False(t, bits[i], "bit %d should be false for 1", i)
		}
	})

	t.Run("max uint32", func(t *testing.T) {
		t.Parallel()
		bits := uint32ToBits(^uint32(0))
		assert.Len(t, bits, 32)
		for i := range 32 {
			assert.True(t, bits[i], "bit %d should be true for max", i)
		}
	})

	t.Run("specific value", func(t *testing.T) {
		t.Parallel()
		// nonce=141 from test vector
		bits := uint32ToBits(141)
		assert.Len(t, bits, 32)
		// Reconstruct the value
		var result uint32
		for i := range 32 {
			if bits[i] {
				result |= 1 << i
			}
		}
		assert.Equal(t, uint32(141), result)
	})
}

func TestMemoToBits(t *testing.T) {
	t.Parallel()

	t.Run("empty memo", func(t *testing.T) {
		t.Parallel()
		bits := memoToBits("")
		assert.Len(t, bits, 34*8)
		// First byte should be type tag (0x01)
		assert.True(t, bits[0], "first bit of type tag")
		for i := 1; i < 8; i++ {
			assert.False(t, bits[i], "bit %d of type tag should be 0", i)
		}
		// Second byte should be length (0)
		for i := 8; i < 16; i++ {
			assert.False(t, bits[i], "length byte should be 0 for empty memo")
		}
	})

	t.Run("short memo", func(t *testing.T) {
		t.Parallel()
		bits := memoToBits("test")
		assert.Len(t, bits, 34*8)
		// First byte: type tag (0x01) = 0b00000001 LSB-first
		assert.True(t, bits[0])
		// Second byte: length (4) = 0b00000100 LSB-first
		assert.False(t, bits[8])
		assert.False(t, bits[9])
		assert.True(t, bits[10]) // bit 2 = 4
	})

	t.Run("max length memo", func(t *testing.T) {
		t.Parallel()
		memo := "12345678901234567890123456789012" // 32 chars
		bits := memoToBits(memo)
		assert.Len(t, bits, 34*8)
		// Second byte: length (32) = 0b00100000 LSB-first
		var length byte
		for i := range 8 {
			if bits[8+i] {
				length |= 1 << i
			}
		}
		assert.Equal(t, byte(32), length)
	})

	t.Run("memo exceeds max length", func(t *testing.T) {
		t.Parallel()
		memo := "123456789012345678901234567890123456" // 36 chars, should truncate to 32
		bits := memoToBits(memo)
		assert.Len(t, bits, 34*8)
		// Second byte: length (32)
		var length byte
		for i := range 8 {
			if bits[8+i] {
				length |= 1 << i
			}
		}
		assert.Equal(t, byte(32), length)
	})
}

func TestTagToBits(t *testing.T) {
	t.Parallel()

	t.Run("payment tag (0)", func(t *testing.T) {
		t.Parallel()
		bits := tagToBits(0)
		assert.Len(t, bits, 3)
		assert.False(t, bits[0])
		assert.False(t, bits[1])
		assert.False(t, bits[2])
	})

	t.Run("delegation tag (1)", func(t *testing.T) {
		t.Parallel()
		bits := tagToBits(1)
		assert.Len(t, bits, 3)
		assert.False(t, bits[0])
		assert.False(t, bits[1])
		assert.True(t, bits[2])
	})

	t.Run("tag 7", func(t *testing.T) {
		t.Parallel()
		bits := tagToBits(7)
		assert.Len(t, bits, 3)
		assert.True(t, bits[0])
		assert.True(t, bits[1])
		assert.True(t, bits[2])
	})
}

func TestNewPaymentMessage(t *testing.T) {
	t.Parallel()

	publicKey, err := DecodePublicKey("B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg")
	require.NoError(t, err)
	receiver, err := DecodePublicKey("B62qrcFstkpqXww1EkSGrqMCwCNho86kuqBd4FrAAUsPxNKdiPzAUsy")
	require.NoError(t, err)

	t.Run("valid payment message", func(t *testing.T) {
		t.Parallel()
		msg, err := NewPaymentMessage(publicKey, receiver, 42, 3, 200, 10000, "test memo")
		require.NoError(t, err)
		assert.NotNil(t, msg)

		// Verify message has expected structure
		fields := msg.Fields()
		bits := msg.Bits()

		// Should have 3 fields (fee payer x, source x, receiver x)
		assert.Len(t, fields, 3)
		// Should have expected number of bits
		// fee(64) + tokenId(64) + isOdd(1) + nonce(32) + validUntil(32) + memo(272) +
		// tag(3) + sourceIsOdd(1) + receiverIsOdd(1) + tokenId(64) + amount(64) + locked(1)
		// Total bits = 64+64+1+32+32+272+3+1+1+64+64+1 = 599
		assert.Len(t, bits, 599)
	})

	t.Run("nil source", func(t *testing.T) {
		t.Parallel()
		msg, err := NewPaymentMessage(nil, receiver, 42, 3, 200, 10000, "test")
		assert.Nil(t, msg)
		assert.Error(t, err)
	})

	t.Run("nil receiver", func(t *testing.T) {
		t.Parallel()
		msg, err := NewPaymentMessage(publicKey, nil, 42, 3, 200, 10000, "test")
		assert.Nil(t, msg)
		assert.Error(t, err)
	})
}

func TestNewDelegationMessage(t *testing.T) {
	t.Parallel()

	publicKey, err := DecodePublicKey("B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg")
	require.NoError(t, err)
	delegate, err := DecodePublicKey("B62qkfHpLpELqpMK6ZvUTJ5wRqKDRF3UHyJ4Kv3FU79Sgs4qpBnx5RR")
	require.NoError(t, err)

	t.Run("valid delegation message", func(t *testing.T) {
		t.Parallel()
		msg, err := NewDelegationMessage(publicKey, delegate, 3, 10, 4000, "test memo")
		require.NoError(t, err)
		assert.NotNil(t, msg)

		// Verify message has expected structure
		fields := msg.Fields()
		bits := msg.Bits()

		// Should have 3 fields (fee payer x, source x, delegate x)
		assert.Len(t, fields, 3)
		// Same bit count as payment
		assert.Len(t, bits, 599)
	})

	t.Run("nil source", func(t *testing.T) {
		t.Parallel()
		msg, err := NewDelegationMessage(nil, delegate, 3, 10, 4000, "test")
		assert.Nil(t, msg)
		assert.Error(t, err)
	})

	t.Run("nil delegate", func(t *testing.T) {
		t.Parallel()
		msg, err := NewDelegationMessage(publicKey, nil, 3, 10, 4000, "test")
		assert.Nil(t, msg)
		assert.Error(t, err)
	})
}

func TestAddPublicKeyToInput(t *testing.T) {
	t.Parallel()

	publicKey, err := DecodePublicKey("B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg")
	require.NoError(t, err)

	msg := new(ROInput).Init()
	err = addPublicKeyToInput(msg, publicKey)
	require.NoError(t, err)

	// Should have 1 field and 1 bit
	assert.Len(t, msg.Fields(), 1)
	assert.Len(t, msg.Bits(), 1)
}
