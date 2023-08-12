package hashing

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

const (
	// AesHashIV is the hash's initialisation vector. We hardcode 32 arbitrary bytes.
	AesHashIV = string("\u00a0\u2001\u2102\uff4f\u2119\u1e54\u0119\u211b\u0387\u33c7\u00A0\u200A")
	// AesBlockSize is the input/output size (in bytes) of the internal block cipher.
	AesBlockSize = aes.BlockSize
	// AesKeySize is the key size (in bytes) for the internal block cipher.
	AesKeySize = 2 * aes.BlockSize
)

// HashTMMOFixedIn (Section 7.4 of [GKWY20](https://eprint.iacr.org/2019/074.pdf)
// is the Tweakable Matyas-Meyer-Oseas construction, using a block cipher (π) as
// an ideal permutation. For an input x and with the following equation:
//
//	TMMO^π (x,i) =  π(π(x)⊕i)⊕π(x)
//
// where i is the tweak, and π(x) is the block cipher, using as key the previous
// output of the TMMO output (the IV for the first block), as prescribed by the
// Matyas-Meyer-Oseas construction. We use AES256 as the block cipher, chained
// using CTR mode to achieve inputs and outputs of size KeySize (32 bytes). The
// hashIv is used as the initial key for the block cipher, and the sessionId is
// used as random (but public) IV for the CTR mode.
func HashTMMOFixedIn(input, hashIv []byte, outputBlockLength int) (digest []byte, err error) {
	// 1) Initialise the cipher with the initialization vector (iv) as key.
	// If no iv is provided, use the hardcoded IV.
	if len(hashIv) == 0 {
		hashIv = []byte(AesHashIV)
	}
	if len(hashIv) < AesKeySize {
		return nil, errs.NewInvalidLength("iv length must be at least %d bytes", AesKeySize)
	}
	blockCipher, err := aes.NewCipher(hashIv[:AesKeySize])
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create block cipher")
	}
	// 2) Parse the input into blocks of the cipher's block size.
	inputLength := len(input)
	if inputLength != AesBlockSize {
		return nil, errs.NewInvalidLength("data length (%d) not equal to CTR Stream length (%d bytes)", inputLength, AesBlockSize)
	}
	// Initialise intermediate values and output.
	digest = make([]byte, outputBlockLength*AesBlockSize)
	permutedBlock := make([]byte, AesBlockSize)
	// 3) Loop over the blocks, applying the TMMO construction at each iteration
	for i := 0; i < outputBlockLength; i++ {
		outputBlock := digest[i*AesBlockSize : (i+1)*AesBlockSize]
		// 3.1) TMMO^π (x,i) - Apply the TMMO to the current block.
		// 3.1.1) π(x) - Apply the block cipher to the current block.
		blockCipher.Encrypt(permutedBlock, input)
		// 3.1.2) π(x)⊕i - XOR the result of the block cipher with the index.
		xorIndex(permutedBlock, outputBlock, int32(i+1))
		// 3.1.3) π(π(x)⊕i) - Apply the block cipher to the result of the XOR.
		blockCipher.Encrypt(outputBlock, outputBlock)
		// 3.1.4) π(π(x)⊕i)⊕π(x) - XOR the two results of the block cipher.
		for j := 0; j < AesBlockSize; j++ {
			outputBlock[j] ^= permutedBlock[j]
		}
		// 3.2) Set the current block as the key for the next iteration.
		if i < outputBlockLength-1 {
			blockCipher, err = aes.NewCipher(outputBlock)
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to re-key block cipher")
			}
		}
	}
	return digest, nil
}

// EncryptAES256CTR encrypts the input using AES256 in CTR mode, with input and
// output of size AesKeySize. It computes just two AES blocks of input-independent
// CTR operations, avoiding the use of the Go `crypto/cipher` library and its
// inefficiencies (see EncryptAES256CTRStream for more info). Note that this
// implementation yields the same result as EncryptAES256CTRStream.
func EncryptAES256CTR(input, output []byte, aesBlockCipher cipher.Block, iv []byte) (err error) {
	if len(input) != AesKeySize || len(output) != AesKeySize {
		return errs.NewInvalidLength("wrong input length")
	}
	if len(iv) == 0 {
		iv = []byte(AesHashIV)
	}
	if aesBlockCipher.BlockSize() != AesBlockSize || len(iv) < AesBlockSize {
		return errs.NewInvalidLength("wrong iv size")
	}
	// Initialise the counter with the iv, the empty output and the block cipher.
	counter := make([]byte, AesBlockSize)
	copy(counter, iv[:AesBlockSize])
	// First AES CTR block (i=0)
	aesBlockCipher.Encrypt(output[:AesBlockSize], counter)
	// Second AES CTR block (i=1)
	counter[AesBlockSize-1]++
	aesBlockCipher.Encrypt(output[AesBlockSize:], counter)
	// XOR the plaintext to get the ciphertext.
	for j := 0; j < 2*AesBlockSize; j++ {
		output[j] ^= input[j]
	}
	return nil
}

// EncryptAES256CTRStream encrypts the input using AES256 in CTR mode, with input
// and output of size KeySize. It uses the Go `crypto/cipher` library to do so,
// following the example in https://go.dev/src/crypto/cipher/example_test.go.
// Internally, XORKeyStream computes the input-independent CTR operations in
// chunks of 32 AES blocks (=512B), calling aes.Encrypt once for each chunk
// (see ctr.refill() for more info).
// Since we know the input and output size to be just 32 bytes (2 AES blocks),
// this is highly inefficient, and thus we use the custom implementation above.
// This function is kept for testing purposes only.
func EncryptAES256CTRStream(input, output []byte, blockCipher cipher.Block, iv []byte) (err error) {
	if len(input) != AesKeySize || len(output) != AesKeySize {
		return errs.NewInvalidLength("wrong input length")
	}
	stream := cipher.NewCTR(blockCipher, iv)
	stream.XORKeyStream(output, input)
	return nil
}

// xorIndex xors the first 4 bytes of the block with the index.
func xorIndex(input, output []byte, index int32) {
	copy(output, input)
	output[0] ^= byte(index >> 24)
	output[1] ^= byte(index >> 16)
	output[2] ^= byte(index >> 8)
	output[3] ^= byte(index)
}
