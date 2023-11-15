/*
This package implements a hash based on Aes as a block cipher. Use it only in cases where the CPU supports AES instructions but doesn't support instructions for your hash of choice (e.g., SHA256 or SHA3).
*/
package tmmohash

import (
	"crypto/aes"
	"crypto/subtle"
	"hash"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/hashing/tmmohash/keyedblock"
)

const (
	// IV is the hash's initialisation vector. We choose 32 arbitrary bytes.
	IV = string("ThereIsNothingUpMySleeveMrCopper")
	// AesBlockSize is the input/output size of the internal AES block cipher. 16B by default.
	AesBlockSize = aes.BlockSize
)

/*
TmmoHash implements an extension of the Tweakable Matyas-Meyer-Oseas (TMMO)
construction (Section 7.4 of [GKWY20](https://eprint.iacr.org/2019/074.pdf),
using a block cipher (π) as an ideal permutation. With an input `x` of size a
single block of π, and an index `i` ∈ [1,2,...,L] (for an output with L blocks
of π), the TMMO construction is defined as:

	digest[i] = TMMO^π (x,i) = π(π(x)⊕i)⊕π(x) 				∀i∈[L]

where π(x) is the block cipher (fixed-key AES, to leverage AES-NI instructions)
using as key the previous output of the TMMO output (the IV for the first block)
as prescribed by the Matyas-Meyer-Oseas construction. We use AES for π with
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
type TmmoHash struct {
	keySize          int                   // key size (in bytes) for the internal block cipher.
	outputBlocks     int                   // Fixed digest size in # AES blocks
	counter          int                   // Hash-wide counter to use as index in TMMO
	keyedBlockCipher keyedblock.KeyedBlock // Hold the underlying block cipher π (AES)
	iv               []byte                // Initialization Vector. Stored to be able to `.Reset()`
	digest           []byte                // Hash output

	// Auxiliary variables. Allocated once and used on every `Write`, thus this
	// implementation is not thread-safe (only one thread per ExtendedTMMO).
	permutedOnceBlock []byte // Store π(x) on every iteration.
	tempKey           []byte // Store the key on every iteration.

	// PRNG variables. Used only when the hash is used as a PRNG.
	prngBytePointer int // Position of the next byte to read from the digest when used as PRNG
}

// NewTmmoHash creates a new TMMO hash object to perform AES-based hashing, setting:
//   - `keySize` selects the size of AES keys in {16, 24, 32} bytes.
//   - `outputSize` (multiple of AesBlockSize==16B) sets the digest size (# of Bytes)
//   - `iv` (optional), an initialization vector of AesKeSize bytes to personalise
//     the hash function (typ. use a session ID).
func NewTmmoHash(keySize, outputSize int, iv []byte) (hash.Hash, error) {
	// 1) Validate the keySize and outputSize
	if (keySize != 16) && (keySize != 24) && (keySize != 32) {
		return nil, errs.NewInvalidArgument("keySize (%dB) must be one of {16, 24, 32}", keySize)
	}
	if outputSize < AesBlockSize || outputSize%AesBlockSize != 0 {
		return nil, errs.NewInvalidArgument("outputSize (%dB) must be a multiple of AesBlockSize (%dB)", outputSize, AesBlockSize)
	}
	// 2) Initialise the cipher with the initialization vector (iv) as key.
	// If no iv is provided, use the hardcoded IV.
	var internalHashIv []byte
	if len(iv) == 0 {
		internalHashIv = []byte(IV)[:keySize]
	} else {
		internalHashIv = make([]byte, len(iv))
		copy(internalHashIv, iv) // Create a copy of the hashIv for Reset
	}
	if len(internalHashIv) < keySize {
		return nil, errs.NewInvalidLength("iv length must be at least %d B (keySize)", keySize)
	}
	tempKey := make([]byte, keySize)
	copy(tempKey, internalHashIv[:keySize])
	blockCipher, err := keyedblock.NewKeyedCipher(tempKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create block cipher")
	}
	// 3) Initialise the digest and the auxiliary variables.
	return &TmmoHash{
		keySize:           keySize,
		outputBlocks:      outputSize / AesBlockSize,
		counter:           0,
		keyedBlockCipher:  blockCipher,
		iv:                internalHashIv,
		digest:            make([]byte, outputSize),
		permutedOnceBlock: make([]byte, AesBlockSize),
		tempKey:           tempKey,
		prngBytePointer:   0,
	}, nil
}

// Write (via the embedded io.Writer interface) adds more data to the running hash.
// It never returns an error.
func (h *TmmoHash) Write(input []byte) (n int, err error) {
	// A) Align the input into blocks of AesBlockSize bytes. Pad 0s if unalligned.
	inputLength := len(input)
	inputBlocks := utils.CeilDiv(inputLength, AesBlockSize)
	if inputLength%AesBlockSize != 0 {
		pad := make([]byte, inputLength%AesBlockSize)
		input = append(input, pad...)
	}
	// 3) Loop over the output blocks, applying TMMO^π (x,i) at each iteration.
	for i := 0; i < h.outputBlocks; i++ {
		outputBlock := h.digest[i*AesBlockSize : (i+1)*AesBlockSize]
		// 3.B) Loop over the input blocks.
		for j := 0; j < inputBlocks; j++ {
			// 3.1) TMMO^π (x,i) - Apply the TMMO to the current block.
			// 3.1.1) π(x) - Apply the block cipher to the current block.
			h.keyedBlockCipher.Encrypt(h.permutedOnceBlock, input[j*AesBlockSize:(j+1)*AesBlockSize])
			// 3.1.2) π(x)⊕i - XOR the result of the block cipher with the index.
			// We increase a hash-level counter on each TMMO call and use it as index.
			h.counter++
			xorIndexBE(h.permutedOnceBlock, outputBlock, int32(h.counter))
			// 3.1.3) π(π(x)⊕i) - Apply the block cipher to the result of the XOR.
			h.keyedBlockCipher.Encrypt(outputBlock, outputBlock)
			// 3.1.4) π(π(x)⊕i)⊕π(x) - XOR the two results of the block cipher.
			subtle.XORBytes(outputBlock, outputBlock, h.permutedOnceBlock)
			// 3.1.B) Refresh the AES key for the next iteration.
			// 	key[1] = key[0] ⊕ key[1]
			subtle.XORBytes(h.tempKey[AesBlockSize:], h.tempKey[AesBlockSize:], h.tempKey[:AesBlockSize])
			// 	key[0] = TMMO^π(x,i)
			copy(h.tempKey[:AesBlockSize], outputBlock)
			h.keyedBlockCipher.SetKey(h.tempKey)
		}
	}
	return len(h.digest), nil
}

// Size returns the number of bytes hashAes.Sum will return.
func (h *TmmoHash) Size() int {
	return len(h.digest)
}

// BlockSize returns the hash's underlying block size. The Write method avoids
// padding if all writes are a multiple of the block size.
func (*TmmoHash) BlockSize() int {
	return AesBlockSize
}

// Reset resets the Hash to its initial state.
func (h *TmmoHash) Reset() {
	h.counter = 0
	copy(h.tempKey, h.iv[:h.keySize])
	blockCipher, err := keyedblock.NewKeyedCipher(h.tempKey)
	if err != nil {
		panic("failed to create block cipher") // panic because Reset doesn't return error
	}
	h.keyedBlockCipher = blockCipher
	bitstring.Memset(h.digest, byte(0))
	bitstring.Memset(h.permutedOnceBlock, byte(0))
}

// Sum appends current hash digest to b after a finalisation. It does not change
// the underlying hash state.
func (h *TmmoHash) Sum(b []byte) (res []byte) {
	// Finalise hash by writing the current hash counter with arbitrary padding.
	// This avoids length extension attacks.

	if len(b) == 0 {
		res = make([]byte, h.Size())
		copy(res, h.digest)
	} else {
		res = append(b, h.digest...)
	}
	return res
}

/* -------------------------------- PRNG ------------------------------------ */
// Seeded PRNG based on Tmmohash, adhering to the PRNG interface defined by NIST SP 800-90A Rev. 1.

// NewTmmoPrng initialises a Tmmohash and uses it as a PRNG. It uses the Tmmohash
// digest as buffer, and fills it on each call to `Reseed` with writeSize bytes,
// using AES with `keySize` bytes of key. An optional `salt` can be also used to
// "personalise" the hash.
func NewTmmoPrng(keySize, bufferSize int, seed, salt []byte) (csprng.CSPRNG, error) {
	h, err := NewTmmoHash(keySize, bufferSize, seed)
	if err != nil {
		return nil, errs.WrapFailed(err, "Could not create Tmmohash as PRNG")
	}
	tmmoPrng, ok := h.(*TmmoHash)
	if !ok {
		return nil, errs.WrapFailed(err, "Could not cast Tmmohash to PRNG")
	}
	if _, err := tmmoPrng.Write(salt); err != nil {
		return nil, errs.WrapFailed(err, "failed to salt TmmoPrng")
	}
	tmmoPrng.prngBytePointer = bufferSize
	return tmmoPrng, nil
}

// Clone creates a copy of the current hash.
func (h *TmmoHash) Clone() csprng.CSPRNG {
	iv := append(make([]byte, 0, len(h.iv)), h.iv...)
	return &TmmoHash{
		keySize:           h.keySize,
		outputBlocks:      h.outputBlocks,
		counter:           h.counter,
		keyedBlockCipher:  h.keyedBlockCipher.Clone(iv),
		iv:                append(make([]byte, 0, len(h.iv)), h.iv...),
		digest:            append(make([]byte, 0, len(h.digest)), h.digest...),
		permutedOnceBlock: append(make([]byte, 0, AesBlockSize), h.permutedOnceBlock...),
		tempKey:           append(make([]byte, 0, h.keySize), h.tempKey...),
		prngBytePointer:   h.prngBytePointer,
	}
}

// New creates a new Tmmohash with the same parameters as the current one.
func (h *TmmoHash) New(seed, salt []byte) (csprng.CSPRNG, error) {
	return NewTmmoPrng(h.keySize, len(h.digest), seed, salt)
}

// Read implements the io.Reader interface. It calls Generate without any salt.
func (h *TmmoHash) Read(buffer []byte) (n int, err error) {
	if err = h.Generate(buffer, nil); err != nil {
		return 0, errs.WrapRandomSampleFailed(err, "failed to read from TmmoPrng")
	}
	return len(buffer), nil
}

// Generate implements the PRNG interface. It reads the hash's digest to make it
// behave like a PRNG, reusing the internal seed and the provided salt at each
// call.
func (h *TmmoHash) Generate(buffer, salt []byte) (err error) {
	bufferBytesIndex, bufferLen := 0, len(buffer)
	// Write the available bytes first.
	availablePrngBytes := len(h.digest) - h.prngBytePointer
	if bufferLen < availablePrngBytes {
		copy(buffer, h.digest[h.prngBytePointer:h.prngBytePointer+bufferLen])
		h.prngBytePointer += bufferLen
		bufferBytesIndex += bufferLen
	} else {
		copy(buffer, h.digest[h.prngBytePointer:])
		h.prngBytePointer = len(h.digest)
		bufferBytesIndex += availablePrngBytes
	}
	// Sample and write bytes in blocks of len(digest). Reseed after each write.
	numReseeds := utils.CeilDiv(bufferLen-bufferBytesIndex, len(h.digest)) - 1
	for i := 0; i < numReseeds; i++ {
		if err := h.Reseed(nil, salt); err != nil {
			return errs.WrapRandomSampleFailed(err, "failed to reseed TmmoPrng in sample block")
		}
		copy(buffer[bufferBytesIndex:bufferBytesIndex+len(h.digest)], h.digest)
		h.prngBytePointer = len(h.digest)
		bufferBytesIndex += len(h.digest)
	}
	// Sample and write the remaining bytes to fill the buffer.
	if remainingBytes := (bufferLen - bufferBytesIndex); remainingBytes != 0 {
		if err := h.Reseed(nil, salt); err != nil {
			return errs.WrapRandomSampleFailed(err, "failed to reseed TmmoPrng one last time")
		}
		h.prngBytePointer = remainingBytes
		copy(buffer[bufferBytesIndex:], h.digest[:h.prngBytePointer])
	}
	return nil
}

// Reseed implements the PRNG interface. It reads the hash's digest to make it
// behave like a PRNG. Uses the `iv` to store the seed.
func (h *TmmoHash) Reseed(seed, salt []byte) (err error) {
	// Use the provided  if no seed is provided, store the new seed otherwise.
	switch seedLen := len(seed); {
	case seedLen == 0:
		seed = h.iv
	case seedLen >= h.keySize:
		h.iv = make([]byte, seedLen)
		copy(h.iv, seed)
	default:
		return errs.NewInvalidLength("seed must be %d bytes", h.keySize)
	}
	// Update the internal hash state with the new seed and reset the prngCounter.
	if _, err := h.Write(append(seed, salt...)); err != nil {
		return errs.WrapFailed(err, "failed to reseed TmmoPrng")
	}
	h.prngBytePointer = len(h.digest)
	return nil
}

// Seed re-initialises the PRNG.
func (h *TmmoHash) Seed(seed, salt []byte) (err error) {
	h.Reset()
	// Copy the seed to the iv and reset with that IV.
	switch seedLen := len(seed); {
	case seedLen == 0:
		h.iv = []byte(IV)[:h.keySize]
	case seedLen < h.keySize:
		return errs.NewInvalidLength("seed length must be at least %d B (keySize)", h.keySize)
	default:
		h.iv = make([]byte, h.keySize)
		copy(h.iv, seed) // Create a copy of the hashIv
	}
	h.Reset()
	// Update the internal hash state with the salt.
	if _, err := h.Write(salt); err != nil {
		return errs.WrapFailed(err, "failed to salt TmmoPrng")
	}
	h.prngBytePointer = len(h.digest)
	return nil
}

func (h *TmmoHash) SecurityStrength() int {
	return h.keySize
}

/* ----------------------------- AUXILIARY ---------------------------------- */
// xorIndexBE xors the first 4 bytes of the block with the index.
func xorIndexBE(input, output []byte, index int32) {
	copy(output, input)
	output[0] ^= byte(index >> 24)
	output[1] ^= byte(index >> 16)
	output[2] ^= byte(index >> 8)
	output[3] ^= byte(index)
}
