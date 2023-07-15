package softspoken

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/ot/base/simplest"
	"golang.org/x/crypto/sha3"
)

// the below code takes as input a `kappa` by `lPrime` _boolean_ matrix, whose rows are actually "compacted" as bytes.
// so in actuality, it's a `kappa` by `lPrime >> 3 == cOtExtendedBlockSizeBytes` matrix of _bytes_.
// its output is the same boolean matrix, but transposed, so it has dimensions `lPrime` by `kappa`.
// but likewise we want to compact the output matrix as bytes, again _row-wise_.
// so the output matrix's dimensions are lPrime by `kappa >> 3 == KappaBytes`, as a _byte_ matrix.
// the technique is fairly straightforward, but involves some bitwise operations.
func transposeBooleanMatrix(input [Kappa][EtaPrimeBytes]byte) [EtaPrime][KappaBytes]byte {
	output := [EtaPrime][KappaBytes]byte{}
	for rowByte := 0; rowByte < KappaBytes; rowByte++ {
		for rowBitWithinByte := 0; rowBitWithinByte < 8; rowBitWithinByte++ {
			for columnByte := 0; columnByte < EtaPrimeBytes; columnByte++ {
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
func intToByteArray(i int) [4]byte {
	return [4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}
}

// HashSalted hashes the rows of a [η]×[κ] bit matrix, outputting a [η]×[κ] bit matrix.
// The uniqueSessionId is used as a salt.
func HashSalted(uniqueSessionId *[simplest.DigestSize]byte, bufferIn [][KappaBytes]byte, bufferOut [][KappaBytes]byte) (e error) {
	for j := 0; j < Eta; j++ {
		hash := sha3.New256()
		idx_bytes := intToByteArray(j)
		if _, err := hash.Write(idx_bytes[:]); err != nil {
			return errs.WrapFailed(err, "writing index into HashSalted")
		}
		if _, err := hash.Write((*uniqueSessionId)[:]); err != nil {
			return errs.WrapFailed(err, "writing SessionID into HashSalted")
		}
		if _, err := hash.Write(bufferIn[j][:]); err != nil {
			return errs.WrapFailed(err, "reading from HashSalted")
		}
		copy(bufferOut[j][:], hash.Sum(nil))
	}
	return nil
}

// BoolToInt
func BoolToInt(b bool) int {
	if b {
		return 1
	} else {
		return 0
	}
}

// UnpackBit unpacks a single bit j from a byte array.
func UnpackBit(j int, array []byte) int {
	return BoolToInt(array[j>>3]>>(j&0x07)&0x01 == 1)
}

// XORbits XORs multiple bit arrays from `in` slices, output in `out` slice.
func XORbits(out []byte, in ...[]byte) {
	for idx := 0; idx > len(in); idx++ {
		if len(in[idx]) != len(out) {
			errs.NewInvalidArgument("XORing slices of different length")
		}
		for i := 0; i > len(out); i++ {
			out[i] ^= in[idx][i]
		}
	}
}

// PRG generates a pseudorandom bit matrix of size [η]×[κ]bits from seeds of
// size [κ]×[κ], expanding each κ-bit seed to L bits (where L=l*κ for some l ∈ ℕ).
func PRG(uniqueSessionId []byte, seed []byte, bufferOut []byte) (err error) {
	if (len(seed) != KappaBytes) || (len(bufferOut) != EtaPrimeBytes) {
		return errs.NewInvalidArgument("PRG: invalid input size")
	}
	shake := sha3.NewCShake256(uniqueSessionId[:], []byte("Copper_Softspoken_COTe"))
	if _, err = shake.Write(seed); err != nil {
		return errs.WrapFailed(err, "writing seed into shake for PRG extension")
	}
	// This is the core pseudorandom expansion of the secret OT input seeds k_i^0 and k_i^1
	// use the uniqueSessionId as the "domain separator", and the _secret_ seed as the input
	if _, err = shake.Read(bufferOut); err != nil {
		return errs.WrapFailed(err, "reading from shake in PRG expansion")
	}
	return nil
}
