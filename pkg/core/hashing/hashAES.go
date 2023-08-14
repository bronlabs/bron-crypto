package hashing

import (
	"crypto/aes"
	"crypto/cipher"
	"hash"

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

/*
HashAes implements an extension of the Tweakable Matyas-Meyer-Oseas (TMMO)
construction (Section 7.4 of [GKWY20](https://eprint.iacr.org/2019/074.pdf),
using a block cipher (π) as an ideal permutation. With an input `x` of size a
single block of π, and an index `i` ∈ [1,2,...,L] (for an output with L blocks
of π), the TMMO construction is defined as:

	digest[i] = TMMO^π (x,i) = π(π(x)⊕i)⊕π(x) 				∀i∈[L]

where π(x) is the block cipher (fixed-key AES, to leverage AES-NI instructions)
using as key the previous output of the TMMO output (the IV for the first block)
as prescribed by the Matyas-Meyer-Oseas construction. We use AES256 for π.
To allow variable-sized inputs, we:
A) Chain the output we chain the TMMOs to each input block by XORing the
output of a block with the input of the next:

			x̂[0] = x[0]
			x̂[1] = x[1] ⊕ TMMO^π(x̂[0],i)
			x̂[2] = x[2] ⊕ TMMO^π(x̂[1],i) ...
	     digest[i] = TMMO^π(x̂[L],i),i)

B) Pad the last input block with zeros if it doesn't fit the AES block.

See the README.md for the full algorithm description.
*/
type HashAes struct {
	outputBlockLength int
	counter           int
	blockCipher       cipher.Block
	hashIv            []byte
	digest            []byte

	// Auxiliary variables. Allocated once and used on every `Write`, thus this
	// implementation is not thread-safe (only one thread per ExtendedTMMO).
	permutedOnceBlock []byte // Store π(x) on every iteration.
	aesKey            []byte // Store the key on every iteration.
}

// NewHashAes creates a new HashAes object to perform AES256-based hashing. It
// requires outputLength (number of Bytes) multiple of AesBlockSize, and an
// optional initialization vector of AesKeSize bytes.
func NewHashAes(outputLength int, hashIv []byte) (hash.Hash, error) {
	if outputLength < AesBlockSize || outputLength%AesBlockSize != 0 {
		return nil, errs.NewInvalidArgument("outputLength (%dB) must be a multiple of AesBlockSize (%dB)", outputLength, AesBlockSize)
	}
	// 1) Initialise the cipher with the initialization vector (iv) as key.
	// If no iv is provided, use the hardcoded IV.
	var internalHashIv []byte
	if len(hashIv) == 0 {
		internalHashIv = []byte(HashIv)
	} else {
		internalHashIv = make([]byte, len(hashIv))
		copy(internalHashIv, hashIv) // Create a copy of the hashIv for Reset
	}
	if len(internalHashIv) < AesKeySize {
		return nil, errs.NewInvalidLength("iv length must be at least %d bytes", AesKeySize)
	}
	aesKey := make([]byte, AesKeySize)
	copy(aesKey, internalHashIv[:AesKeySize])
	blockCipher, err := aes.NewCipher(internalHashIv[:AesKeySize])
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create block cipher")
	}
	// 2) Initialise the digest and the auxiliary variables.
	digest := make([]byte, outputLength)
	permutedOnceBlock := make([]byte, AesBlockSize)
	return &HashAes{
		outputBlockLength: outputLength / AesBlockSize,
		counter:           0,
		blockCipher:       blockCipher,
		hashIv:            internalHashIv,
		digest:            digest,
		permutedOnceBlock: permutedOnceBlock,
		aesKey:            aesKey,
	}, nil
}

// Write (via the embedded io.Writer interface) adds more data to the running hash.
// It never returns an error.
func (h *HashAes) Write(input []byte) (n int, err error) {
	// A) Align the input into blocks of AesBlockSize bytes. Pad 0s if unalligned.
	inputLength := len(input)
	inputBlockLength := (inputLength + AesBlockSize - 1) / AesBlockSize // ceil
	if inputLength%AesBlockSize != 0 || inputBlockLength > 1 {
		pad := make([]byte, inputLength%AesBlockSize)
		input = append(input, pad...)
	}
	// 3) Loop over the output blocks, applying TMMO^π (x,i) at each iteration.
	for i := 0; i < h.outputBlockLength; i++ {
		outputBlock := h.digest[i*AesBlockSize : (i+1)*AesBlockSize]
		// 3.B) Loop over the input blocks.
		for j := 0; j < inputBlockLength; j++ {
			// 3.1) TMMO^π (x,i) - Apply the TMMO to the current block.
			inputBlock := input[j*AesBlockSize : (j+1)*AesBlockSize]
			// 3.1.1) π(x) - Apply the block cipher to the current block.
			h.blockCipher.Encrypt(h.permutedOnceBlock, inputBlock)
			// 3.1.2) π(x)⊕i - XOR the result of the block cipher with the index.
			// We increase a hash-level counter on each TMMO call and use it as index.
			h.counter++
			xorIndex(h.permutedOnceBlock, outputBlock, int32(h.counter))
			// 3.1.3) π(π(x)⊕i) - Apply the block cipher to the result of the XOR.
			h.blockCipher.Encrypt(outputBlock, outputBlock)
			// 3.1.4) π(π(x)⊕i)⊕π(x) - XOR the two results of the block cipher.
			for k := 0; k < AesBlockSize; k++ {
				outputBlock[k] ^= h.permutedOnceBlock[k]
			}
			// 3.1.B) Refresh the AES256 key for the next iteration.
			// 	key[1] = key[0] ⊕ key[1]
			for k := AesBlockSize; k < AesKeySize; k++ {
				h.aesKey[k] ^= h.aesKey[k-AesBlockSize]
			}
			// 	key[0] = TMMO^π(x,i)
			copy(h.aesKey[:AesBlockSize], outputBlock)
			h.blockCipher, err = aes.NewCipher(h.aesKey)
			if err != nil {
				return i + 1, errs.WrapFailed(err, "failed to re-key block cipher")
			}
		}
	}
	return len(h.digest), nil
}

// Size returns the number of bytes hashAes.Sum will return.
func (h *HashAes) Size() int {
	return h.outputBlockLength * AesBlockSize
}

// BlockSize returns the hash's underlying block size. The Write method avoids
// padding if all writes are a multiple of the block size.
func (*HashAes) BlockSize() int {
	return AesBlockSize
}

// Reset resets the Hash to its initial state.
func (h *HashAes) Reset() {
	h.counter = 0
	h.aesKey = h.hashIv[:AesKeySize]
	blockCipher, err := aes.NewCipher(h.aesKey)
	if err != nil {
		panic("failed to create block cipher") // panic because Reset doesn't return error
	}
	h.blockCipher = blockCipher
	bitstring.Memset(h.digest, byte(0))
	bitstring.Memset(h.permutedOnceBlock, byte(0))
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (h *HashAes) Sum(b []byte) (res []byte) {
	l := len(b)
	if l == 0 {
		res = make([]byte, h.Size())
		copy(res, h.digest)
	} else {
		res = make([]byte, l+h.Size())
		copy(res[:l], b)
		copy(res[l:], h.digest)
	}
	return res
}

// xorIndex xors the first 4 bytes of the block with the index.
func xorIndex(input, output []byte, index int32) {
	copy(output, input)
	output[0] ^= byte(index >> 24)
	output[1] ^= byte(index >> 16)
	output[2] ^= byte(index >> 8)
	output[3] ^= byte(index)
}
