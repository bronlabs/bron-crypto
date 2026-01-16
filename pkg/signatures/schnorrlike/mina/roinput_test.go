package mina_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/mina"
)

func Test_BitsToPackedFields(t *testing.T) {
	t.Parallel()
	input := new(mina.ROInput).Init()
	input.AddString("someveryverylongmessagecmrewiugriuhtrlugchmtrlugchslrifudjtrfunhvgudysrthvgnkyudrtgcvdnkurytcnhgkdtuyrnhgkryutcghksrecyuhgkstruhgmsrtucghslrutcghslrtuhgkdsfuhgcmsruthcvgslrtuhgmlrtuichslrmutsrthdl")
	fields := input.PackToFields()

	require.Len(t, fields, 7)
	require.Equal(t, "6739959678053839808442019806815009096953251624254956745969670397973851731662", fields[0].Cardinal().Big().Text(10))
	require.Equal(t, "11694274828623079122518667601523414095790905048332939675937030108127164021337", fields[1].Cardinal().Big().Text(10))
	require.Equal(t, "15109057306232126396170098590048975416355454488766875820599404248434383677153", fields[2].Cardinal().Big().Text(10))
	require.Equal(t, "19710143195313378682873744829237720688259603907450714948479184137717694444985", fields[3].Cardinal().Big().Text(10))
	require.Equal(t, "17227962557078458526949747460171157970072782053868244093602941461684486071830", fields[4].Cardinal().Big().Text(10))
	require.Equal(t, "25659442655828297319107427068349186374832281178012109346410085717571425458971", fields[5].Cardinal().Big().Text(10))
	require.Equal(t, "3721075549420", fields[6].Cardinal().Big().Text(10))
}

func TestROInputInit(t *testing.T) {
	t.Parallel()

	input := new(mina.ROInput).Init()
	assert.NotNil(t, input)
	assert.Empty(t, input.Fields())
	assert.Empty(t, input.Bits())
}

func TestROInputClone(t *testing.T) {
	t.Parallel()

	t.Run("empty input", func(t *testing.T) {
		original := new(mina.ROInput).Init()
		cloned := original.Clone()

		assert.NotNil(t, cloned)
		assert.Empty(t, cloned.Fields())
		assert.Empty(t, cloned.Bits())
	})

	t.Run("with fields", func(t *testing.T) {
		original := new(mina.ROInput).Init()
		field := pasta.NewPallasBaseField().One()
		original.AddFields(field)

		cloned := original.Clone()

		assert.Len(t, cloned.Fields(), 1)
		assert.True(t, cloned.Fields()[0].Equal(field))
	})

	t.Run("with bits", func(t *testing.T) {
		original := new(mina.ROInput).Init()
		original.AddBits(true, false, true)

		cloned := original.Clone()

		assert.Equal(t, original.Bits(), cloned.Bits())
	})

	t.Run("modifications don't affect original", func(t *testing.T) {
		original := new(mina.ROInput).Init()
		original.AddBits(true, false)

		cloned := original.Clone()
		cloned.AddBits(true, true, true)

		assert.Len(t, original.Bits(), 2)
		assert.Len(t, cloned.Bits(), 5)
	})
}

func TestROInputAddFields(t *testing.T) {
	t.Parallel()

	input := new(mina.ROInput).Init()

	field1 := pasta.NewPallasBaseField().One()
	field2 := pasta.NewPallasBaseField().One()
	field2 = field2.Add(field2) // 2

	input.AddFields(field1)
	assert.Len(t, input.Fields(), 1)

	input.AddFields(field2)
	assert.Len(t, input.Fields(), 2)

	// Add multiple at once
	field3 := pasta.NewPallasBaseField().One()
	field4 := pasta.NewPallasBaseField().One()
	input.AddFields(field3, field4)
	assert.Len(t, input.Fields(), 4)
}

func TestROInputAddString(t *testing.T) {
	t.Parallel()

	t.Run("empty string", func(t *testing.T) {
		input := new(mina.ROInput).Init()
		input.AddString("")
		assert.Empty(t, input.Bits())
	})

	t.Run("single char", func(t *testing.T) {
		input := new(mina.ROInput).Init()
		input.AddString("a") // 'a' = 0x61 = 0b01100001
		bits := input.Bits()
		assert.Len(t, bits, 8)
		// MSB first per byte: 0, 1, 1, 0, 0, 0, 0, 1
		assert.False(t, bits[0])
		assert.True(t, bits[1])
		assert.True(t, bits[2])
		assert.False(t, bits[3])
		assert.False(t, bits[4])
		assert.False(t, bits[5])
		assert.False(t, bits[6])
		assert.True(t, bits[7])
	})

	t.Run("multiple chars", func(t *testing.T) {
		input := new(mina.ROInput).Init()
		input.AddString("ab")
		bits := input.Bits()
		assert.Len(t, bits, 16)
	})
}

func TestROInputAddBits(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		input := new(mina.ROInput).Init()
		input.AddBits()
		assert.Empty(t, input.Bits())
	})

	t.Run("single bit", func(t *testing.T) {
		input := new(mina.ROInput).Init()
		input.AddBits(true)
		bits := input.Bits()
		assert.Len(t, bits, 1)
		assert.True(t, bits[0])
	})

	t.Run("multiple bits", func(t *testing.T) {
		input := new(mina.ROInput).Init()
		input.AddBits(true, false, true, false)
		bits := input.Bits()
		assert.Len(t, bits, 4)
		assert.True(t, bits[0])
		assert.False(t, bits[1])
		assert.True(t, bits[2])
		assert.False(t, bits[3])
	})

	t.Run("append multiple times", func(t *testing.T) {
		input := new(mina.ROInput).Init()
		input.AddBits(true)
		input.AddBits(false)
		input.AddBits(true, false)
		bits := input.Bits()
		assert.Len(t, bits, 4)
		assert.True(t, bits[0])
		assert.False(t, bits[1])
		assert.True(t, bits[2])
		assert.False(t, bits[3])
	})
}

func TestROInputFields(t *testing.T) {
	t.Parallel()

	t.Run("returns copy", func(t *testing.T) {
		input := new(mina.ROInput).Init()
		field := pasta.NewPallasBaseField().One()
		input.AddFields(field)

		fields1 := input.Fields()
		fields2 := input.Fields()

		// Should be equal but not the same slice
		assert.Len(t, fields2, len(fields1))
		assert.True(t, fields1[0].Equal(fields2[0]))
	})
}

func TestROInputBits(t *testing.T) {
	t.Parallel()

	t.Run("nil bits", func(t *testing.T) {
		input := new(mina.ROInput)
		bits := input.Bits()
		assert.Nil(t, bits)
	})

	t.Run("empty bits", func(t *testing.T) {
		input := new(mina.ROInput).Init()
		bits := input.Bits()
		assert.Empty(t, bits)
	})

	t.Run("returns copy", func(t *testing.T) {
		input := new(mina.ROInput).Init()
		input.AddBits(true, false)

		bits1 := input.Bits()
		bits2 := input.Bits()

		// Should be equal
		assert.Equal(t, bits1, bits2)

		// Modifying one shouldn't affect the other
		bits1[0] = false
		bits3 := input.Bits()
		assert.True(t, bits3[0])
	})
}

func TestROInputPackToFields(t *testing.T) {
	t.Parallel()

	t.Run("empty input", func(t *testing.T) {
		input := new(mina.ROInput).Init()
		packed := input.PackToFields()
		assert.Empty(t, packed)
	})

	t.Run("only fields", func(t *testing.T) {
		input := new(mina.ROInput).Init()
		field := pasta.NewPallasBaseField().One()
		input.AddFields(field)

		packed := input.PackToFields()
		assert.Len(t, packed, 1)
		assert.True(t, packed[0].Equal(field))
	})

	t.Run("only bits", func(t *testing.T) {
		input := new(mina.ROInput).Init()
		// Add 8 bits
		for range 8 {
			input.AddBits(true)
		}

		packed := input.PackToFields()
		assert.Len(t, packed, 1)
	})

	t.Run("bits spanning multiple fields", func(t *testing.T) {
		input := new(mina.ROInput).Init()
		// Add 255 bits (fills one field at 254 bits + 1 bit in next)
		for range 255 {
			input.AddBits(true)
		}

		packed := input.PackToFields()
		assert.Len(t, packed, 2)
	})

	t.Run("fields and bits combined", func(t *testing.T) {
		input := new(mina.ROInput).Init()
		field := pasta.NewPallasBaseField().One()
		input.AddFields(field)
		input.AddBits(true, false, true)

		packed := input.PackToFields()
		assert.Len(t, packed, 2) // 1 field + 1 packed bits field
	})
}

func TestROInputMarshalJSON(t *testing.T) {
	t.Parallel()

	t.Run("empty input", func(t *testing.T) {
		input := new(mina.ROInput).Init()
		data, err := input.MarshalJSON()
		require.NoError(t, err)

		var result []string
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("with fields", func(t *testing.T) {
		input := new(mina.ROInput).Init()
		field := pasta.NewPallasBaseField().One()
		input.AddFields(field)

		data, err := input.MarshalJSON()
		require.NoError(t, err)

		var result []string
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)
		assert.Len(t, result, 1)
	})

	t.Run("with bits", func(t *testing.T) {
		input := new(mina.ROInput).Init()
		input.AddBits(true, false, true)

		data, err := input.MarshalJSON()
		require.NoError(t, err)

		var result []string
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)
		// Bits get packed into a field
		assert.Len(t, result, 1)
	})
}

func TestROInputIntegration(t *testing.T) {
	t.Parallel()

	t.Run("message signing workflow", func(t *testing.T) {
		// Create a message like in real signing
		input := new(mina.ROInput).Init()

		// Add a field element (like a public key x coordinate)
		field := pasta.NewPallasBaseField().One()
		input.AddFields(field)

		// Add some bits (like nonce, valid_until, etc.)
		for range 64 {
			input.AddBits(false)
		}
		input.AddBits(true) // isOdd flag

		// Add a string (like memo)
		input.AddString("test")

		// Verify the structure
		assert.Len(t, input.Fields(), 1)
		assert.NotEmpty(t, input.Bits())

		// Pack to fields for hashing
		packed := input.PackToFields()
		assert.NotEmpty(t, packed)
	})
}
