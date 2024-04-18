package bitstring_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
)

func TestReverseBytes(t *testing.T) {
	
	t.Run("test for non empty array", func(t *testing.T){
		t.Parallel()

		inputMatrix :=  []byte {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}

		//reverse of revese should be the same os original
		result := bitstring.ReverseBytes(inputMatrix)
		result = bitstring.ReverseBytes(result)

		require.Equal(t, result, inputMatrix)
	})

	t.Run("test for empty array", func(t *testing.T) {
		t.Parallel()

		inputMatrix :=  []byte {}
        result := bitstring.ReverseBytes(inputMatrix)

        require.Equal(t, result, inputMatrix)
	})
//super large array??
}

func TestPadToLeft(t *testing.T) {

	t.Run("Test with positive padLen", func(t *testing.T) {
		t.Parallel()

		inputMatrix :=  [][]byte {
			{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			{},
			{0x21},
		}
		inputPadLengths := 2
		expectedOutput := [][]byte {
			{0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			{0x00, 0x00},
			{0x00, 0x00, 0x21},
		}

		for i:= 0; i < len(inputMatrix); i++ {
			require.Equal(t, expectedOutput[i], bitstring.PadToLeft(inputMatrix[i], inputPadLengths))
		}
	})
	t.Run("Test with negative padLen", func(t *testing.T) {
		t.Parallel()

		inputMatrix :=  [][]byte {
			{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			{},
			{0x21},
		}
		inputPadLengths := -2
		excpectedOutput := inputMatrix

		for i:= 0; i < len(inputMatrix); i++ {
			require.Equal(t, excpectedOutput[i], bitstring.PadToLeft(inputMatrix[i], inputPadLengths))
		}
	})

	t.Run("Test with zero padLen", func(t *testing.T) {
		t.Parallel()

		inputMatrix :=  [][]byte {
			{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			{},
			{0x21},
		}
		inputPadLengths := 0
		excpectedOutput := inputMatrix

		for i:= 0; i < len(inputMatrix); i++ {
			require.Equal(t, excpectedOutput[i], bitstring.PadToLeft(inputMatrix[i], inputPadLengths))
		}
	})
}

func TestPadToRight(t *testing.T) {

	t.Run("Test with positive padLen", func(t *testing.T) {
		t.Parallel()

		inputMatrix :=  [][]byte {
			{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			{},
			{0x21},
		}
		inputPadLengths := 2
		expectedOutput := [][]byte {
			{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0x00, 0x00},
			{0x00, 0x00},
			{0x21, 0x00, 0x00},
		}
		for i:= 0; i < len(inputMatrix); i++ {
			require.Equal(t, expectedOutput[i], bitstring.PadToRight(inputMatrix[i], inputPadLengths))
		}
	})
	t.Run("Test with negative padLen", func(t *testing.T) {
		t.Parallel()

		inputMatrix :=  [][]byte {
			{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			{},
			{0x21},
		}
		inputPadLengths := -2
		excpectedOutput := inputMatrix

		for i:= 0; i < len(inputMatrix); i++ {
			require.Equal(t, excpectedOutput[i], bitstring.PadToRight(inputMatrix[i], inputPadLengths))
		}
	})

	t.Run("Test with zero padLen", func(t *testing.T) {
		t.Parallel()

		inputMatrix :=  [][]byte {
			{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			{},
			{0x21},
		}
		inputPadLengths := 0
		excpectedOutput := inputMatrix
		for i:= 0; i < len(inputMatrix); i++ {
			require.Equal(t, excpectedOutput[i], bitstring.PadToRight(inputMatrix[i], inputPadLengths))
		}
	})
}

func TestTransposeBooleanMatrix(t *testing.T) {
	t.Run("Test with valid input", func(t *testing.T) {
		t.Parallel()

		inputMatrix := [][]byte{
			{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			{0x21, 0x43, 0x65, 0x87, 0xA9, 0xCB},
			{0x31, 0x53, 0x75, 0x97, 0xB9, 0xDB},
			{0x41, 0x63, 0x85, 0xA7, 0xC9, 0xEB},
			{0x51, 0x73, 0x95, 0xB7, 0xD9, 0xFB},
			{0x61, 0x83, 0xA5, 0xC7, 0xE9, 0x0B},
			{0x71, 0x93, 0xB5, 0xD7, 0xF9, 0x1B},
			{0x81, 0xA3, 0xC5, 0xE7, 0x09, 0x2B},
		}

		transposedMatrix, err := bitstring.TransposePackedBits(inputMatrix)
		require.NoError(t, err)
		for i := 0; i < len(inputMatrix); i++ {
			for j := 0; j < len(transposedMatrix); j++ {
				// Check that the bit at position i in the jth row of the input matrix.
				// is equal to the bit at position j in the ith row of the transposed matrix.
				// using bitstring.SelectBit (careful! it takes a byte array as input)
				output1 := bitstring.PackedBits(inputMatrix[i]).Select(j)
				output2 := bitstring.PackedBits(transposedMatrix[j]).Select(i)
	
				require.Equal(t,
					output1,
					output2)
			}
		}    
	})
	t.Run("Test for input not having rows%8==0", func(t *testing.T){
		t.Parallel()

		inputMatrix := [][]byte{
			{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			{0x21, 0x43, 0x65, 0x87, 0xA9, 0xCB},
			{0x31, 0x53, 0x75, 0x97, 0xB9, 0xDB},
			{0x41, 0x63, 0x85, 0xA7, 0xC9, 0xEB},
			{0x51, 0x73, 0x95, 0xB7, 0xD9, 0xFB},
			{0x61, 0x83, 0xA5, 0xC7, 0xE9, 0x0B},
			{0x71, 0x93, 0xB5, 0xD7, 0xF9, 0x1B},
		}
		_, err := bitstring.TransposePackedBits(inputMatrix)
		require.Error(t, err)
	})
	t.Run("Testing 1D matrix", func(t *testing.T){
		t.Parallel()

		inputMatrix := [][]byte{
			{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
		}
		_, err := bitstring.TransposePackedBits(inputMatrix)
		require.Error(t, err)
	})
}

func TestByteSubLE(t *testing.T) {

	t.Run("Test One", func(t *testing.T) {
		t.Parallel()

		inputMatrix := []byte{0x05, 0x01, 0x00, 0x00}
		expectedOutput := []byte{0x04, 0x01, 0x00, 0x00}
		bitstring.ByteSubLE(inputMatrix)
		
		require.Equal(t, expectedOutput, inputMatrix)
	})

	t.Run("Test Two", func(t *testing.T) {
		t.Parallel()

		inputMatrix := []byte{0x00, 0x00, 0x01, 0x00}
		expectedOutput := []byte{0xFF, 0xFF, 0x00, 0x00}
		bitstring.ByteSubLE(inputMatrix)
		
		require.Equal(t, expectedOutput, inputMatrix)
	})

	t.Run("Test Three", func(t *testing.T) {
		inputMatrix := []byte{0x00, 0x00, 0x00, 0x01}
		expectedOutput := []byte{0xFF, 0xFF, 0xFF, 0x00}
		bitstring.ByteSubLE(inputMatrix)
		
		require.Equal(t, expectedOutput, inputMatrix)
	})

	t.Run("Test Three", func(t *testing.T) {
		t.Parallel()

		inputMatrix := []byte{0x00, 0x00, 0x00, 0x00}
		expectedOutput := []byte{0xFF, 0xFF, 0xFF, 0xFF}
		bitstring.ByteSubLE(inputMatrix)
		
		require.Equal(t, expectedOutput, inputMatrix)
	})
}

func TestToBytesLE(t *testing.T) {

	t.Run("Test for Positive int", func(t *testing.T) {
		t.Parallel()

		i := 123456789
		expectedOutput := []byte {0x15, 0xCD, 0x5B, 0x07}
		
		result := bitstring.ToBytesLE(i)
		require.Equal(t, expectedOutput, result)
	})

	t.Run("Test for Negative int", func(t *testing.T) {
		t.Parallel()

		i := -123456789
		expectedOutput := []byte {0xEB, 0x32, 0xA4, 0xF8}
		
		result := bitstring.ToBytesLE(i)
		require.Equal(t, expectedOutput, result)
	})

	t.Run("Test for Zero", func(t *testing.T) {
		t.Parallel()

		i := 0
        expectedOutput := []byte {0x00, 0x00, 0x00, 0x00}
        
        result := bitstring.ToBytesLE(i)
        require.Equal(t, expectedOutput, result)
	})

	t.Run("Test for max int32", func(t *testing.T) {
		t.Parallel()

		i := 2147483647
		expectedOutput := []byte {0xFF, 0xFF, 0xFF, 0x7F}

		result := bitstring.ToBytesLE(i)
		require.Equal(t, expectedOutput, result)
	})

	t.Run("Test for max -int32", func(t *testing.T) {
		t.Parallel()

		i := -2147483648
		expectedOutput := []byte {0x00, 0x00, 0x00, 0x80}

		result := bitstring.ToBytesLE(i)
		require.Equal(t, expectedOutput, result)
	})
}

func TestTruncateWithEllipsis(t *testing.T) {

	t.Run("maxLength being bigger than len(text)", func(t *testing.T) {
		t.Parallel()

		text:= "Hello"
		maxLength := 10
		expectedOutput := "Hello"
		result := bitstring.TruncateWithEllipsis(text, maxLength)

		require.Equal(t, expectedOutput, result)
	})

	t.Run("maxLength being equal to len(text)", func(t *testing.T) {
		t.Parallel()

		text:= "HelloWorld"
        maxLength := 10
        expectedOutput := "HelloWorld"
        result := bitstring.TruncateWithEllipsis(text, maxLength)

        require.Equal(t, expectedOutput, result)
	})

	t.Run("maxLength being less than len(text)", func(t *testing.T) {
		t.Parallel()

		text:= "Hello, World!"
        maxLength := 10
        expectedOutput := "Hello, Wor...(3)"
        result := bitstring.TruncateWithEllipsis(text, maxLength)

        require.Equal(t, expectedOutput, result)
	})

	t.Run("empty string", func(t *testing.T) {
		text:= ""
        maxLength := 10
        expectedOutput := ""
        result := bitstring.TruncateWithEllipsis(text, maxLength)

        require.Equal(t, expectedOutput, result)
	})

	// t.Run("Test Five", func(t *testing.T) {
	// 	text:= "Hello, World!"
    //     maxLength := -1
    //     expectedOutput := "Hello, World!"
    //     result := bitstring.TruncateWithEllipsis(text, maxLength)

    //     require.Equal(t, expectedOutput, result)
	// })
}

func TestMemclr (t *testing.T) {
	//should I include unit,unit8,... test as well ?

    t.Run("Test for matrix of type int", func(t *testing.T) {
		t.Parallel()

        inputMatrix := []int{1, 2, 3, 4}
        expectedOutput := []int{0, 0, 0, 0}
        bitstring.Memclr(inputMatrix)
        
        require.Equal(t, expectedOutput, inputMatrix)
    })

	t.Run("Test for matrix of type int8", func(t *testing.T) {
		t.Parallel()

		inputMatrix := []int8{10, 20, 30, 40}
		expectedOutput := []int8{0, 0, 0, 0}
		bitstring.Memclr(inputMatrix)

		require.Equal(t, expectedOutput, inputMatrix)
	})

	t.Run("Test for matrix of type int16", func(t *testing.T) {
		t.Parallel()

		inputMatrix := []int16{100, 200, 300, 4000}
		expectedOutput := []int16{0, 0, 0, 0}
		bitstring.Memclr(inputMatrix)

		require.Equal(t, expectedOutput, inputMatrix)
	})
	t.Run("Test for matrix of type int32", func(t *testing.T) {
		t.Parallel()

		inputMatrix := []int32{1000000000, 2000000000, 300000000, 400000000}
        expectedOutput := []int32{0, 0, 0, 0}
        bitstring.Memclr(inputMatrix)

        require.Equal(t, expectedOutput, inputMatrix)
	})
	t.Run("Test for matrix of type int64", func(t *testing.T) {
		t.Parallel()

		inputMatrix := []int64{1000000000000000000, 2000000000000000000, 3000000000000000000, 4000000000000000000}
        expectedOutput := []int64{0, 0, 0, 0}
        bitstring.Memclr(inputMatrix)

        require.Equal(t, expectedOutput, inputMatrix)
	})

	t.Run("Test for an empty matrix", func(t *testing.T) {
		t.Parallel()

		inputMatrix := []int{}
        expectedOutput := []int{}
        bitstring.Memclr(inputMatrix)

        require.Equal(t, expectedOutput, inputMatrix)
	})
}