package hashing

import (
	"crypto/aes"

	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

const (
	iv = string(`\x10\x21\x32\x43\x54\x65\x76\x87` +
		`\x98\xa9\xba\xcb\xdc\xed\xfe\x0f` +
		`\x0e\x1d\x2c\x3b\x4a\x59\x68\x77` +
		`\x86\x95\xa4\xb3\xc2\xd1\xe0\xff`)
	BlockSize = 32 // 256 bits
)

// HashTMMO (from Section 7.4 of [GKWY20](https://eprint.iacr.org/2019/074.pdf)
// is the Tweakable Matyas-Meyer-Oseas construction, using a block cipher (π) as
// an ideal permutation. For an input x and with the following equation:
//
//	TMMO^π (x,i) =  π(π(x)⊕i)⊕π(x)
//
// where i is the tweak, and π(x) is the block cipher, using as key the previous
// output of the TMMO output (the IV for the first block), as prescribed by the
// Matyas-Meyer-Oseas construction.
func HashTMMO(input []byte) (digest []byte, err error) {
	// 1) Initialize the cipher (AES256 by default) with the IV as key.
	key := []byte(iv)[BlockSize:]
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create cipher")
	}
	// 2) Parse the input into blocks of the cipher's block size.
	inputLen := len(input)
	blockSize := blockCipher.BlockSize()
	if inputLen%blockSize != 0 {
		panic("data length must be a multiple of the block length")
	}
	inputBlocks := inputLen / blockSize
	permutedBlock := make([]byte, blockSize)
	outputBlock := make([]byte, blockSize)

	// 3) Loop over the blocks, applying the TMMO construction at each iteration
	for i := 0; i < inputBlocks; i++ {
		// 3.1) TMMO^π (x,i) - Apply the TMMO construction to the current block.
		// 3.1.1) π(x[i]) - Apply the block cipher to the current block.
		blockCipher.Encrypt(permutedBlock, input[i*blockSize:(i+1)*blockSize])
		// 3.1.2) π(x[i])⊕i - XOR the result of the block cipher with the index.
		xorIndexInPlace(int32(i), permutedBlock, outputBlock)
		// 3.1.3) π(π(x[i])⊕i) - Apply the block cipher to the result of the XOR.
		blockCipher.Encrypt(outputBlock, outputBlock)
		// 3.1.4) π(π(x[i])⊕i)⊕π(x[i]) - XOR the two results of the block cipher.
		for i := 0; i < BlockSize; i++ {
			outputBlock[i] ^= permutedBlock[i]
		}
		// 3.2) Set the current block as the key for the next iteration.
		// TODO: check if key is copied in the block cipher:
		//   - If so, avoid this first copy.
		//   - If not, avoid the creation of a new block cipher.
		if i < inputBlocks-1 {
			copy(key, outputBlock)
			blockCipher, err = aes.NewCipher(key)
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to create cipher")
			}
		}
	}
	return outputBlock, nil

}

// xorIndexInPlace xors the first 4 bytes of the block with the index.
func xorIndexInPlace(index int32, input, output []byte) {
	copy(output, input)
	output[0] ^= byte(index >> 24)
	output[1] ^= byte(index >> 16)
	output[2] ^= byte(index >> 8)
	output[3] ^= byte(index)
}
