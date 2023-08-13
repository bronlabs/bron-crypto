package hashing

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

const (
	// HashIv is the hash's initialisation vector. We hardcode 32 arbitrary bytes.
	HashIv = string("\u00a0\u2001\u2102\uff4f\u2119\u1e54\u0119\u211b\u0387\u33c7\u00A0\u200A")
	// AesBlockSize is the input/output size of the internal AES block cipher. 16B by default.
	AesBlockSize = aes.BlockSize
	// AesKeySize is the key size (in bytes) for the internal block cipher. Set to 32B (AES256).
	AesKeySize = 2 * aes.BlockSize
)

// HashAes implements an extension of the Tweakable Matyas-Meyer-Oseas (TMMO)
// construction (Section 7.4 of [GKWY20](https://eprint.iacr.org/2019/074.pdf),
// using a block cipher (π) as an ideal permutation. With an input `x` of size a
// single block of π, and an index `i` ∈ [1,2,...,L] (for an output with L blocks
// of π), the TMMO construction is defined as:
//
//	digest[i] = TMMO^π (x,i) = π(π(x)⊕i)⊕π(x) 				∀i∈[L]
//
// where π(x) is the block cipher (fixed-key AES, to leverage AES-NI instructions)
// using as key the previous output of the TMMO output (the IV for the first block)
// as prescribed by the Matyas-Meyer-Oseas construction. We use AES256 for π.
// To allow variable-sized inputs, we:
// (*) Chain the output we chain the TMMOs to each input block by XORing the
// output of a block with the input of the next:
//
//			x̂[0] = x[0]
//			x̂[1] = x[1] ⊕ TMMO^π(x̂[0],i),i)
//			x̂[2] = x[2] ⊕ TMMO^π(x̂[1],i),i) ...
//	     digest[i] = TMMO^π(x̂[L],i),i)
//
// (+) Pad the last input block with zeros if it doesn't fit the AES block.
func HashAes(input, hashIv []byte, outputBlockLength int) (digest []byte, err error) {
	// 1) Initialise the cipher with the initialization vector (iv) as key.
	// If no iv is provided, use the hardcoded IV.
	if len(hashIv) == 0 {
		hashIv = []byte(HashIv)
	}
	if len(hashIv) < AesKeySize {
		return nil, errs.NewInvalidLength("iv length must be at least %d bytes", AesKeySize)
	}
	blockCipher, err := aes.NewCipher(hashIv[:AesKeySize])
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create block cipher")
	}
	// 2) (+) Align the input into blocks of AesBlockSize bytes. Pad if unalligned.
	inputLength := len(input)
	inputBlockLength := (inputLength + AesBlockSize - 1) / AesBlockSize // ceil
	if inputLength%AesBlockSize != 0 || inputBlockLength > 1 {
		pad := make([]byte, inputLength%AesBlockSize)
		input = append(input, pad...)
	}
	// Initialise intermediate values and output.
	digest = make([]byte, outputBlockLength*AesBlockSize)
	permutedOnceBlock := make([]byte, AesBlockSize) // Store π(x)
	chainedInputBlock := make([]byte, AesBlockSize) // Store x[j] ⊕ TMMO^π(x̂[j-1],i),i)
	// 3) Loop over the output blocks, applying TMMO^π (x,i) at each iteration.
	for i := 0; i < outputBlockLength; i++ {
		outputBlock := digest[i*AesBlockSize : (i+1)*AesBlockSize]
		// (*) Loop over the input blocks.
		for j := 0; j < inputBlockLength; j++ {
			// (*) If the input `x` contains more than one block, we chain
			// the TMMOs to each input block by XORing the output of a block
			// with the input of the next: x̂[j] = x[j] ⊕ TMMO^π(x̂[j-1],i),i)
			inputBlock := input[j*AesBlockSize : (j+1)*AesBlockSize]
			if j < inputBlockLength-1 {
				for k := 0; k < AesBlockSize; k++ {
					chainedInputBlock[k] = inputBlock[k] ^ outputBlock[k]
				}
				inputBlock = chainedInputBlock // Reference the auxiliary input block
			}
			// 3.1) TMMO^π (x,i) - Apply the TMMO to the current block.
			// 3.1.1) π(x) - Apply the block cipher to the current block.
			blockCipher.Encrypt(permutedOnceBlock, inputBlock)
			// 3.1.2) π(x)⊕i - XOR the result of the block cipher with the index.
			// For the index, we combine the output block index `i` (spelled in
			// the TMMO) with the input block index `j`.
			index := int32((j + 1) + i*inputBlockLength)
			xorIndex(permutedOnceBlock, outputBlock, index)
			// 3.1.3) π(π(x)⊕i) - Apply the block cipher to the result of the XOR.
			blockCipher.Encrypt(outputBlock, outputBlock)
			// 3.1.4) π(π(x)⊕i)⊕π(x) - XOR the two results of the block cipher.
			for k := 0; k < AesBlockSize; k++ {
				outputBlock[k] ^= permutedOnceBlock[k]
			}
		}
		// 3.2) Set the current output block as the key for the next iteration.
		if i < outputBlockLength-1 {
			blockCipher, err = aes.NewCipher(outputBlock)
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to re-key block cipher")
			}
		}
	}
	return digest, nil
}

type ExtendedTMMO struct {
	outputBlockLength int
	blockCipher       cipher.Block
	hashIv            []byte
	digest            []byte

	// Auxiliary variables. Allocated once and used on every `Write`, thus this
	// implementation is not thread-safe (only one thread per ExtendedTMMO).
	permutedOnceBlock []byte // Store π(x)
	chainedInputBlock []byte // Store x[j] ⊕ TMMO^π(x̂[j-1],i),i)
}

func NewHashAes(hashIv []byte, outputBlockLength int) (*ExtendedTMMO, error) {
	if outputBlockLength < 1 {
		return nil, errs.NewInvalidArgument("outputBlockLength must be at least 1")
	}
	// 1) Initialise the cipher with the initialization vector (iv) as key.
	// If no iv is provided, use the hardcoded IV.
	var internalHashIv []byte
	if len(hashIv) == 0 {
		internalHashIv = []byte(HashIv)
	} else {
		internalHashIv = make([]byte, len(hashIv))
		copy(internalHashIv, hashIv) // Create our own copy of the hashIv
	}
	if len(internalHashIv) < AesKeySize {
		return nil, errs.NewInvalidLength("iv length must be at least %d bytes", AesKeySize)
	}
	blockCipher, err := aes.NewCipher(internalHashIv[:AesKeySize])
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create block cipher")
	}
	digest := make([]byte, outputBlockLength*AesBlockSize) // Store the final digest
	permutedOnceBlock := make([]byte, AesBlockSize)        // Store π(x)
	chainedInputBlock := make([]byte, AesBlockSize)        // Store x[j] ⊕ TMMO^π(x̂[j-1],i),i)
	return &ExtendedTMMO{
		outputBlockLength: outputBlockLength,
		blockCipher:       blockCipher,
		hashIv:            internalHashIv,
		digest:            digest,
		permutedOnceBlock: permutedOnceBlock,
		chainedInputBlock: chainedInputBlock,
	}, nil
}

// Size returns the number of bytes hashAes.Sum will return.
func (h *ExtendedTMMO) Size() int {
	return h.outputBlockLength * AesBlockSize
}

// BlockSize returns the hash's underlying block size. The Write method avoids
// padding if all writes are a multiple of the block size.
func (*ExtendedTMMO) BlockSize() int {
	return AesBlockSize
}

// Reset resets the Hash to its initial state.
func (h *ExtendedTMMO) Reset() {
	blockCipher, err := aes.NewCipher(h.hashIv[:AesKeySize])
	if err != nil {
		panic("failed to create block cipher") // hash.Hash.Reset doesn't return error
	}
	h.blockCipher = blockCipher
	bitstring.Memset(h.digest, byte(0))
	bitstring.Memset(h.permutedOnceBlock, byte(0))
	bitstring.Memset(h.chainedInputBlock, byte(0))
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (h *ExtendedTMMO) Sum(b []byte) []byte {
	if len(b) == 0 {
		b = make([]byte, h.outputBlockLength*AesBlockSize)
		copy(b, h.digest)
		return b
	} else {
		return append(b, h.digest...)
	}
}

// Write (via the embedded io.Writer interface) adds more data to the running hash.
// It never returns an error.
func Write(input []byte) (n int, err error) {
	n = len(input)
	return
}

// xorIndex xors the first 4 bytes of the block with the index.
func xorIndex(input, output []byte, index int32) {
	copy(output, input)
	output[0] ^= byte(index >> 24)
	output[1] ^= byte(index >> 16)
	output[2] ^= byte(index >> 8)
	output[3] ^= byte(index)
}
