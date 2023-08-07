package softspoken

import (
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

// TransposeBooleanMatrix transposes a 2D matrix of "packed" bits (represented in
// groups of 8 bits per bytes), yielding a new 2D matrix of "packed" bits. If we
// were to unpack the bits, inputMatrixBits[i][j] == outputMatrixBits[j][i].
func transposeBooleanMatrix(inputMatrix *[Kappa][ZetaPrimeBytes]byte) [ZetaPrime][KappaBytes]byte {
	outputMatrix := [ZetaPrime][KappaBytes]byte{}
	for rowByte := 0; rowByte < KappaBytes; rowByte++ {
		for rowBitWithinByte := 0; rowBitWithinByte < 8; rowBitWithinByte++ {
			for columnByte := 0; columnByte < ZetaPrimeBytes; columnByte++ {
				for columnBitWithinByte := 0; columnBitWithinByte < 8; columnBitWithinByte++ {
					rowBit := rowByte<<3 + rowBitWithinByte
					columnBit := columnByte<<3 + columnBitWithinByte
					// Grab the corresponding  bit at input[rowBit][columnBit]
					bitAtInputRowBitColumnBit := inputMatrix[rowBit][columnByte] >> columnBitWithinByte & 0x01
					// Place the bit at output[columnBit][rowBit]
					shiftedBit := bitAtInputRowBitColumnBit << rowBitWithinByte
					outputMatrix[columnBit][rowByte] |= shiftedBit
				}
			}
		}
	}
	return outputMatrix
}

// HashSalted hashes the κ-bit length rows of a [ξ]×[κ] bit matrix, outputting rows of
// ω×κ bits in a [ξ]×[ω]×[κ] bit matrix. The uniqueSessionId is used as a salt.
func HashSalted(
	uniqueSessionId *[]byte,
	bufferIn [][KappaBytes]byte,
	bufferOut [][OTeWidth][KappaBytes]byte,
) (e error) {
	if (len(bufferIn) < Zeta) || (len(bufferOut) != Zeta) {
		return errs.NewInvalidArgument("HashSalted: invalid input size")
	}
	for i := 0; i < Zeta; i++ {
		hash := sha3.NewCShake256((*uniqueSessionId), []byte("Copper_Softspoken_COTe"))
		idx_bytes := bitstring.IntToByteArray(i)
		if _, err := hash.Write(idx_bytes[:]); err != nil {
			return errs.WrapFailed(err, "writing index into HashSalted")
		}
		if _, err := hash.Write(bufferIn[i][:]); err != nil {
			return errs.WrapFailed(err, "writing input to HashSalted")
		}
		flatBufferOut := make([]byte, OTeWidth*KappaBytes)
		_, err := hash.Read(flatBufferOut)
		if err != nil {
			return errs.WrapFailed(err, "reading digest from HashSalted")
		}
		for k := 0; k < OTeWidth; k++ {
			copy(bufferOut[i][k][:], flatBufferOut[k*KappaBytes:(k+1)*KappaBytes])
		}
	}
	return nil
}

// PRG generates a pseudorandom bit matrix of size [η]×[κ]bits from seeds of
// size [κ]×[κ], expanding each κ-bit seed to L bits (where L=l*κ for some l ∈ ℕ).
func PRG(uniqueSessionId, seed, bufferOut []byte) (err error) {
	if (len(seed) != KappaBytes) || (len(bufferOut) != ZetaPrimeBytes) {
		return errs.NewInvalidArgument("PRG: invalid input size")
	}
	shake := sha3.NewCShake256(uniqueSessionId, []byte("Copper_Softspoken_COTe"))
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
