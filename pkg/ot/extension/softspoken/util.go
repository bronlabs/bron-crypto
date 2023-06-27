package softspoken

// the below code takes as input a `kappa` by `lPrime` _boolean_ matrix, whose rows are actually "compacted" as bytes.
// so in actuality, it's a `kappa` by `lPrime >> 3 == cOtExtendedBlockSizeBytes` matrix of _bytes_.
// its output is the same boolean matrix, but transposed, so it has dimensions `lPrime` by `kappa`.
// but likewise we want to compact the output matrix as bytes, again _row-wise_.
// so the output matrix's dimensions are lPrime by `kappa >> 3 == KappaBytes`, as a _byte_ matrix.
// the technique is fairly straightforward, but involves some bitwise operations.
func transposeBooleanMatrix(input [Kappa][LPrimeBytes]byte) [LPrime][KappaBytes]byte {
	output := [LPrime][KappaBytes]byte{}
	for rowByte := 0; rowByte < KappaBytes; rowByte++ {
		for rowBitWithinByte := 0; rowBitWithinByte < 8; rowBitWithinByte++ {
			for columnByte := 0; columnByte < LPrimeBytes; columnByte++ {
				for columnBitWithinByte := 0; columnBitWithinByte < 8; columnBitWithinByte++ {
					rowBit := rowByte<<3 + rowBitWithinByte
					columnBit := columnByte<<3 + columnBitWithinByte
					// the below code grabs the _bit_ at input[rowBit][columnBit], if input were a viewed as a boolean matrix.
					// in reality, it's packed into bytes, so instead we have to grab the `columnBitWithinByte`th bit within the appropriate byte.
					bitAtInputRowBitColumnBit := input[rowBit][columnByte] >> columnBitWithinByte & 0x01
					// now that we've grabbed the bit we care about, we need to write it into the appropriate place in the output matrix
					// the output matrix is also packed---but in the "opposite" way (the short dimension is packed, instead of the long one)
					// what we're going to do is take the _bit_ we got, and shift it by rowBitWithinByte.
					// this has the effect of preparing for us to write it into the appropriate place into the output matrix.
					shiftedBit := bitAtInputRowBitColumnBit << rowBitWithinByte
					output[columnBit][rowByte] |= shiftedBit
				}
			}
		}
	}
	return output
}

// Convert from int to byte array
func intToByteArr(i int) [4]byte {
	return [4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}
}
