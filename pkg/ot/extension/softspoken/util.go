package softspoken

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"golang.org/x/crypto/sha3"
)

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

func binaryFieldMul(A []byte, B []byte) []byte {
	// multiplies `A` and `B` in the finite field of order 2^256.
	// The reference is Hankerson, Vanstone and Menezes, Guide to Elliptic Curve Cryptography. https://link.springer.com/book/10.1007/b97644
	// `A` and `B` are both assumed to be 32-bytes slices. here we view them as little-endian coordinate representations of degree-255 polynomials.
	// the multiplication takes place modulo the irreducible (over F_2) polynomial f(X) = X^256 + X^10 + X^5 + X^2 + 1. see Table A.1.
	// the techniques we use are given in section 2.3, Binary field arithmetic.
	// for the multiplication part, we use Algorithm 2.34, "Right-to-left comb method for polynomial multiplication".
	// for the reduction part, we use a variant of the idea of Figure 2.9, customized to our setting.
	const W = 64             // the machine word width, in bits.
	const t = 4              // the number of words needed to represent a polynomial.
	c := make([]uint64, 2*t) // result
	a := make([]uint64, t)
	b := make([]uint64, t+1)  // will hold a copy of b, shifted by some amount
	for i := 0; i < 32; i++ { // "condense" `A` and `B` into word-vectors, instead of byte-vectors
		a[i>>3] |= uint64(A[i]) << (i & 0x07 << 3)
		b[i>>3] |= uint64(B[i]) << (i & 0x07 << 3)
	}
	for k := 0; k < W; k++ {
		for j := 0; j < t; j++ {
			// conditionally add a copy of (the appropriately shifted) B to C, depending on the appropriate bit of A
			// do this in constant-time; i.e., independent of A.
			// technically, in each time we call this, the right-hand argument is a public datum,
			// so we could arrange things so that it's _not_ constant-time, but the variable-time stuff always depends on something public.
			// better to just be safe here though and make it constant-time anyway.
			mask := -(a[j] >> k & 0x01) // if A[j] >> k & 0x01 == 1 then 0xFFFFFFFFFFFFFFFF else 0x0000000000000000
			for i := 0; i < t+1; i++ {
				c[j+i] ^= b[i] & mask // conditionally add B to C{j}
			}
		}
		for i := t; i > 0; i-- {
			b[i] = b[i]<<1 | b[i-1]>>63
		}
		b[0] <<= 1
	}
	// multiplication complete; begin reduction.
	// things become actually somewhat simpler in our case, because the degree of the polynomial is a multiple of the word size
	// the technique to come up with the numbers below comes essentially from going through the exact same process as on page 54,
	// but with the polynomial f(X) = X^256 + X^10 + X^5 + X^2 + 1 above instead, and with parameters m = 256, W = 64, t = 4.
	// the idea is exactly as described informally on that page, even though this particular polynomial isn't explicitly treated.
	for i := 2*t - 1; i >= t; i-- {
		c[i-4] ^= c[i] << 10
		c[i-3] ^= c[i] >> 54
		c[i-4] ^= c[i] << 5
		c[i-3] ^= c[i] >> 59
		c[i-4] ^= c[i] << 2
		c[i-3] ^= c[i] >> 62
		c[i-4] ^= c[i]
	}
	C := make([]byte, 32)
	for i := 0; i < 32; i++ {
		C[i] = byte(c[i>>3] >> (i & 0x07 << 3)) // truncate word to byte
	}
	return C
}

// HashSalted hashes the rows of a [L]×[κ] bit matrix, outputting a [L]×[κ] bit matrix.
// The uniqueSessionId is used as a salt.
func HashSalted(uniqueSessionId []byte, bufferIn [][KappaBytes]byte) (BufferOut [][KappaBytes]byte, e error) {
	var bufferOut [L][KappaBytes]byte
	for j := 0; j < L; j++ {
		hash := sha3.New256()
		idx_bytes := intToByteArr(j)
		if _, err := hash.Write(idx_bytes[:]); err != nil {
			return nil, errs.WrapFailed(err, "writing index into HashSalted")
		}
		if _, err := hash.Write(uniqueSessionId); err != nil {
			return nil, errs.WrapFailed(err, "writing SessionID into HashSalted")
		}
		if _, err := hash.Write(bufferIn[j][:]); err != nil {
			return nil, errs.WrapFailed(err, "reading from HashSalted")
		}
		copy(bufferOut[j][:], hash.Sum(nil))
	}
	return bufferOut[:], nil
}

// UnpackBit unpacks a single bit j from a byte array.
func UnpackBit(j int, array []byte) (bit bool) {
	return array[j>>3]>>(j&0x07)&0x01 == 1
}
