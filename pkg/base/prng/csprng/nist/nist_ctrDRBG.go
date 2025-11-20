package nist

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"math/bits"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/mathutils"
)

type CtrDRBG struct {
	aesBlockCipher cipher.Block
	vLo            uint64
	vHi            uint64
	key            []byte
	keySize        int
	reseedCounter  uint64
}

// NewCtrDRBG creates a new CTR_DRBG instance for a given keySize.
func NewCtrDRBG(keySize int) *CtrDRBG {
	return &CtrDRBG{
		aesBlockCipher: nil,
		vLo:            0,
		vHi:            0,
		key:            make([]byte, keySize),
		keySize:        keySize,
		reseedCounter:  0,
	}
}

// Clone returns a copy of the CTR_DRBG.
func (ctrDrbg *CtrDRBG) Clone() *CtrDRBG {
	aesBlockCipher, err := aes.NewCipher(ctrDrbg.key)
	if err != nil {
		panic(err.Error() + ", Failed to create block cipher in clone.")
	}
	return &CtrDRBG{
		aesBlockCipher: aesBlockCipher,
		vLo:            ctrDrbg.vLo,
		vHi:            ctrDrbg.vHi,
		key:            append(make([]byte, 0, ctrDrbg.keySize), ctrDrbg.key...),
		keySize:        ctrDrbg.keySize,
		reseedCounter:  ctrDrbg.reseedCounter,
	}
}

// KeySize returns the key length of the internal block cipher.
func (ctrDrbg *CtrDRBG) KeySize() int {
	return ctrDrbg.keySize
}

// BlockSize returns the block size of the internal block cipher.
func (*CtrDRBG) BlockSize() int {
	return aes.BlockSize
}

// SeedSize returns the length of the seed material, equal to KeySize + BlockSize.
func (ctrDrbg *CtrDRBG) SeedSize() int {
	return ctrDrbg.keySize + aes.BlockSize
}

// setKey sets the key of the internal block cipher to `key`. If `key` is nil,
// the key is set to all zeros.
func (ctrDrbg *CtrDRBG) SetKey(key []byte) (err error) {
	switch len(key) {
	case 0:
		ctrDrbg.key = make([]byte, ctrDrbg.keySize)
	case ctrDrbg.keySize:
		if n := copy(ctrDrbg.key, key); n != ctrDrbg.keySize {
			return errs.NewLength("key copy went wrong")
		}
	default:
		return errs.NewLength("key has wrong length")
	}
	ctrDrbg.aesBlockCipher, err = aes.NewCipher(ctrDrbg.key)
	if err != nil {
		return errs.WrapFailed(err, "failed to set aes cipher key")
	}
	return nil
}

// update updates the internal state of the CTR_DRBG using the provided_data.
// It implements CTR_DRBG_Update as described in SP800-90A section 10.2.1.2.
func (ctrDrbg *CtrDRBG) Update(providedData []byte) (err error) {
	// +. Treat providedData==nil as SeedSize zeroed bytes.
	if (len(providedData) != ctrDrbg.SeedSize()) && (len(providedData) != 0) {
		return errs.NewLength("provided data has the wrong length (%d != %d)", len(providedData), ctrDrbg.SeedSize())
	}
	// 1. temp = Nil
	// +. Allocate space for temp
	tempBlocks := mathutils.CeilDiv(ctrDrbg.SeedSize(), aes.BlockSize)
	temp := make([]byte, tempBlocks*aes.BlockSize)
	// 2. WHILE (len(temp) < seedLen) DO
	for i := range tempBlocks {
		// 2.1. V = (V+1) mod 2^blocklen
		var c uint64
		ctrDrbg.vLo, c = bits.Add64(ctrDrbg.vLo, 1, 0)
		ctrDrbg.vHi, _ = bits.Add64(ctrDrbg.vHi, 0, c)
		vBytes := slices.Concat(binary.BigEndian.AppendUint64(nil, ctrDrbg.vHi), binary.BigEndian.AppendUint64(nil, ctrDrbg.vLo))
		// 2.2. output_block = Block_Encrypt(Key, V).
		// 2.3. temp = temp || output_block.
		tempBlock := temp[i*aes.BlockSize : (i+1)*aes.BlockSize]
		ctrDrbg.aesBlockCipher.Encrypt(tempBlock, vBytes)
	}
	// 3. temp = leftmost(temp, seedLen)
	temp = temp[:ctrDrbg.SeedSize()]
	// 4. temp = temp ⊕ provided_data.
	if len(providedData) > 0 { // +. If providedData is all zeros (nil), temp is unaffected.
		for j := 0; j < len(temp); j++ {
			temp[j] ^= providedData[j]
		}
	}
	// 5. Key = leftmost(temp, keylen).
	if err = ctrDrbg.SetKey(temp[:ctrDrbg.keySize]); err != nil {
		return errs.WrapFailed(err, "Could not set the block cipher key")
	}
	// 6. V = rightmost (temp, blocklen).
	vBytes := temp[ctrDrbg.keySize:]
	ctrDrbg.vHi = binary.BigEndian.Uint64(vBytes[0:8])
	ctrDrbg.vLo = binary.BigEndian.Uint64(vBytes[8:16])
	return nil
}

// Instantiate prepares the PRNG for its use. The entropy input may or may not
// have full entropy; in either case, a nonce is required. The total input length
// must be equal to `.seedLength()`. The nonce must conform to SP800-90A section
// 8.6.7. This function implements CTR_DRBG_Instantiate_algorithm as specified
// in SP800-90A section 10.2.1.3.2.
func (ctrDrbg *CtrDRBG) Instantiate(entropyInput, nonce, personalizationString []byte) (err error) {
	// 1. seed_material = entropy_input || nonce || personalization_string.
	seedMaterial := make([]byte, 0, len(entropyInput)+len(nonce)+len(personalizationString))
	seedMaterial = append(seedMaterial, entropyInput...)
	seedMaterial = append(seedMaterial, nonce...)
	seedMaterial = append(seedMaterial, personalizationString...)
	// 2. seed_material = df(seed_material, seedlen).
	seedMaterial, err = ctrDrbg.BlockCipherDF(seedMaterial, ctrDrbg.SeedSize())
	if err != nil {
		return errs.WrapFailed(err, "Cannot derive seed material")
	}
	// 3. Key = 0^keylen.
	if err = ctrDrbg.SetKey(nil); err != nil {
		return errs.WrapFailed(err, "Could not set the block cipher key")
	}
	// 4. V = 0^blocklen.
	ctrDrbg.vLo = 0
	ctrDrbg.vHi = 0
	// 5. (Key, V) = CTR_DRBG_Update(seed_material, Key, V).
	if err = ctrDrbg.Update(seedMaterial); err != nil {
		return errs.WrapFailed(err, "Could not update PRNG internal state")
	}
	// 6. reseed_counter = 1.
	ctrDrbg.reseedCounter = 1
	return nil
}

// Reseed refreshes the PRNG with a new seed and prepares it for its use. It
// implements CTR_DRBG_Reseed_algorithm, specified in SP800-90A section 10.2.1.4.2.
func (ctrDrbg *CtrDRBG) Reseed(entropyInput, additionalInput []byte) (err error) {
	// 1. seed_material = entropy_input || additional_input.
	seedMaterial := make([]byte, 0, len(entropyInput)+len(additionalInput))
	seedMaterial = append(seedMaterial, entropyInput...)
	seedMaterial = append(seedMaterial, additionalInput...)
	// 2. seed_material = Block_Cipher_df(seed_material, seedlen).
	seedMaterial, err = ctrDrbg.BlockCipherDF(seedMaterial, ctrDrbg.SeedSize())
	if err != nil {
		return errs.WrapFailed(err, "Cannot reseed the prng")
	}
	// 3. (Key, V) = CTR_DRBG_Update (seed_material, Key, V).
	if err = ctrDrbg.Update(seedMaterial); err != nil {
		return errs.WrapFailed(err, "Could not update PRNG internal state")
	}
	// 4. reseed_counter = 1.
	ctrDrbg.reseedCounter = 1
	return nil
}

// generate generates pseudorandom bits employing a derivation function. It
// implements CTR_DRBG_Generate_algorithm, described in SP800-90A section 10.2.1.5.2.
func (ctrDrbg *CtrDRBG) Generate(outputBuffer, additionalInput []byte) (err error) {
	// +. Get the requested_number_of_bits from the length of the output buffer.
	requestedNumberOfBytes := len(outputBuffer)
	requestedNumberOfBlocks := mathutils.CeilDiv(requestedNumberOfBytes, aes.BlockSize)
	// 1. IF (reseed_counter > reseed_interval), then return an indication that a
	// reseed is required.
	if ctrDrbg.reseedCounter > reseedInterval {
		return errs.NewMissing("PRNG must be reseeded before generating more bits.")
	}
	// 2. IF (additional_input != Nil), then
	if len(additionalInput) > 0 {
		// 2.1. additional_input = Block_Cipher_df(additional_input, seedlen).
		additionalInput, err = ctrDrbg.BlockCipherDF(additionalInput, ctrDrbg.SeedSize())
		if err != nil {
			return errs.WrapFailed(err, "Could not apply the derivation function")
		}
		// 2.2. (Key, V) = CTR_DRBG_Update(additional_input, Key, V).
		if err = ctrDrbg.Update(additionalInput); err != nil {
			return errs.WrapFailed(err, "Could not update PRNG internal state")
		}
	} else { // ELSE additional_input = 0^seedlen. (Implicit, set to nil instead)
		additionalInput = nil
	}
	// 3. temp = Nil.
	// +. Allocate space for all the requested blocks.
	temp := make([]byte, requestedNumberOfBlocks*aes.BlockSize)
	// 4. WHILE(len(temp) < requested_number_of_bits) DO
	for i := range requestedNumberOfBlocks {
		// 4.1. V = (V+1) mod 2^blocklen.
		var c uint64
		ctrDrbg.vLo, c = bits.Add64(ctrDrbg.vLo, 1, 0)
		ctrDrbg.vHi, _ = bits.Add64(ctrDrbg.vHi, 0, c)
		vBytes := slices.Concat(binary.BigEndian.AppendUint64(nil, ctrDrbg.vHi), binary.BigEndian.AppendUint64(nil, ctrDrbg.vLo))
		// 4.2. output_block = Block_Encrypt(Key, V).
		// 4.3. temp = temp || output_block.
		outputBlock := temp[i*aes.BlockSize : (i+1)*aes.BlockSize]
		ctrDrbg.aesBlockCipher.Encrypt(outputBlock, vBytes)
	}
	// 5. returned_bits = leftmost(temp, requested_number_of_bits).
	copy(outputBuffer, temp[:requestedNumberOfBytes])
	// 6. (Key, V) = CTR_DRBG_Update(additional_input, Key, V).
	if err = ctrDrbg.Update(additionalInput); err != nil {
		return errs.WrapFailed(err, "Could not update PRNG internal state")
	}
	// 7. reseed_counter = reseed_counter + 1.
	ctrDrbg.reseedCounter++
	return nil
}

/* .--------------------------- AUXILIARY FUNCTIONS ------------------------. */

// BlockCipherDF implements the derivation function `Block_Cipher_df` as specified
// in SP800-90A section 10.3.2.
func (ctrDrbg *CtrDRBG) BlockCipherDF(inputString []byte, noOfBytesToReturn int) (requestedBytes []byte, err error) {
	// 1. IF (no_of_bits_to_return > max_number_of_bits): return ERROR_FLAG, Nil
	if noOfBytesToReturn > maxNumberOfBytesDF {
		return nil, errs.NewLength("no_of_bits_to_return > max_number_of_bits")
	}
	// 2. L = len(input_string)/8.
	l := uint32(len(inputString))
	// 3. N = no_of_bits_to_return/8.
	n := uint32(noOfBytesToReturn)
	// 5. Pad S with zeros, if necessary.
	// WHILE (len (S) mod outlen) != 0, DO {S = S || 0x00}
	sBlocks := mathutils.CeilDiv(int(4+4+l+1), aes.BlockSize)
	s := make([]byte, sBlocks*aes.BlockSize) // Allocate l, n, inputString, 0x80 and zero pads of #5
	// 4. Prepend the string length and the requested length of the output to the
	//   input_string. S = L || N || input_string || 0x80.
	binary.BigEndian.PutUint32(s[:4], l)
	binary.BigEndian.PutUint32(s[4:8], n)
	copy(s[8:8+l], inputString)
	s[8+l] = 0x80
	// 6. temp = Nil.
	// +. Calculate `len(temp)` and initialise `temp` buffer deterministically.
	tempBlocks := mathutils.CeilDiv(ctrDrbg.SeedSize(), aes.BlockSize)
	temp := make([]byte, tempBlocks*aes.BlockSize) // Allocate space for key and iv.
	// 7. i = 0 (uint32) --> In #9.
	// 8. K = leftmost(0x00010203...1D1E1F, keylen).
	aesCipher, err := aes.NewCipher([]byte(ivKey)[:ctrDrbg.keySize])
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create aes cipher")
	}
	// 9. WHILE (len(temp) < keylen + outlen), DO
	// +. Copy the `S` in the BCC input only once. It remains static.
	ivNs := make([]byte, aes.BlockSize, aes.BlockSize+len(s))
	ivNs = append(ivNs, s...) // (IV || S), with uninitialized IV.
	for i := range tempBlocks {
		// 9.1. IV = i || 0^(outlen - len(i)).
		if i > 0 {
			clear(ivNs[:aes.BlockSize])
		}
		binary.BigEndian.PutUint32(ivNs[:aes.BlockSize], uint32(i))
		// 9.2. temp = temp || BCC (K, (IV || S)).
		BCC(aesCipher, ivNs, temp[i*aes.BlockSize:(i+1)*aes.BlockSize])
		// 9.3. i = i + 1.
	}
	// 10. K = leftmost(temp, keylen).
	aesCipher, err = aes.NewCipher(temp[:ctrDrbg.keySize])
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create aes cipher")
	}
	// 11. X = select (temp, keylen+1, keylen+outlen).
	var x, xOut []byte
	x = temp[ctrDrbg.keySize:ctrDrbg.SeedSize()]
	// 12) temp = Nil.
	// +. Calculate the output size and initialise `temp` buffer deterministically.
	requestedBlocks := mathutils.CeilDiv(noOfBytesToReturn, aes.BlockSize)
	requestedBytes = make([]byte, requestedBlocks*aes.BlockSize)
	// 13. WHILE (len(temp) < number_of_bits_to_return) DO
	for i := range requestedBlocks {
		// 13.1. X = Block_Encrypt (K, X).
		// 13.2. temp = temp || X.
		xOut = requestedBytes[i*aes.BlockSize : (i+1)*aes.BlockSize]
		aesCipher.Encrypt(xOut, x)
		x = xOut
	}
	// 14. requested_bits = leftmost (temp, number_of_bits_to_return).
	requestedBytes = requestedBytes[:noOfBytesToReturn]
	return requestedBytes, nil
}

// BCC (Block Cipher Chain) implements a chained encryption using the provided
// block cipher. Function specified in SP800-90A section 10.3.3. The block cipher
// has been previously initialised with the key. Given a `data` input of length
// `n*aes.BlockSize` bytes, encrypts all the blocks in a chain using the (AES)
// block cipher, yielding a single block of aes.BlockSize bytes as output.
func BCC(aesCipher cipher.Block, data, outputBlock []byte) {
	// +. Validate inputs and initialise auxiliary variables.
	if (len(data)%aes.BlockSize != 0) || (len(outputBlock) != aes.BlockSize) {
		panic("input/output length of wrong size")
	}
	var dataBlock []byte
	inputBlock := make([]byte, aes.BlockSize)
	// 1. chaining_value = 0^outlen. Set the first chaining value to outlen zeros.
	clear(outputBlock) // chaining_value
	// 2. n = len(data)/outlen.
	n := len(data) / aes.BlockSize
	// 4. For i = 1 to n do
	for i := range n {
		// 3. Split data into n blocks of outlen bits each, from left to right.
		dataBlock = data[i*aes.BlockSize : (i+1)*aes.BlockSize]
		// 4.1. input_block = chaining_value ⊕ block[i].
		for j := range aes.BlockSize {
			inputBlock[j] = outputBlock[j] ^ dataBlock[j]
		}
		// 4.2. chaining_value = Block_Encrypt(Key, input_block).
		aesCipher.Encrypt(outputBlock, inputBlock)
	}
}
