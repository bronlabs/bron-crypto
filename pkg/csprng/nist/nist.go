package nist

import (
	"crypto/aes"
	crand "crypto/rand"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
)

const (
	// AesBlockSize is the input/output size of the internal AES block cipher. 16B by default.
	AesBlockSize = aes.BlockSize
	// ivKey is the initial key used to initialise the PRNG.
	ivKey = string(
		"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" +
			"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
	)
	// Parameters defined at Table 3 of section 10.2.1 in SP800-90A Rev. 1.
	//------------- Parameter ---------//---- Value ---//--- Name/s in SP800-90A ---//.
	reseedInterval          = 1 << 48  // 2^48 times   //  `reseed_interval`
	maxNumberOfBytesDF      = 512 >> 3 // 512 bits     //  `max_number_of_bits`
	maxNumberOfBytesRequest = 1 << 16  // 2^19 bit     //  `max_number_of_bits_per_request`
	maxLength               = 1 << 32  // 2^35 bits    //  `max_length`, `max_additional_input_length`,
	// .                                               //   `max_personalization_string_length`.
)

// PrngNist corresponds to an instantiated PRNG based on a block cipher from NIST SP-800-90A rev. 1.
type PrngNist struct {
	entropySource io.Reader // Source used to sample truly random seeds
	ctrDrbg       *CtrDRBG  // Internal PRNG based on AES block cipher in CTR mode.
}

// NewNistPRNG creates a PRNG as specified in SP-800-90A section 10.2. The PRNG uses
// the AES block cipher. The general instantiation is specified in section 9.1.
// The `keySize` parameter must be one of {16, 24, 32} for the corresponding AES
// block cipher. There are two truly random elements to seed this PRNG:
//
//  1. A fresh entropyInput of >=`AesKeySize` Bytes. Sampled from entropySource (AesKeySize Bytes) if not provided.
//  2. A fresh nonce with >=`AesKeySize/2` Bytes. Sampled from entropySource (AesBlockSize Bytes) if not provided.
//
// The (optional) `personalization` can be used to "salt" this PRNG. In the
// context of MPC protocols, the SessionID could be used.
func NewNistPRNG(keySize int, entropySource io.Reader, entropyInput, nonce, personalization []byte) (prng csprng.CSPRNG, err error) {
	NistPrng := new(PrngNist)
	// 1. IF (requested_security_strength > ... --> Skipped, security_strength = keyLen.
	// 2. IF prediction_resistance_flag... --> Skipped, No prediction resistance.
	// 3. IF (len(personalization_string) > max_personalization_string_length) --> error.
	if int64(len(personalization)) > maxLength {
		return nil, errs.NewInvalidLength("personalization too large")
	}
	// 4. Set security_strength = keyLen.
	if (keySize != 16) && (keySize != 24) && (keySize != 32) {
		return nil, errs.NewInvalidArgument("keySize must be one of {16 (AES128), 24 (AES192), 32 (AES256)}")
	}
	securityStrength := keySize
	// 5. Nil step.
	if entropySource != nil {
		NistPrng.entropySource = entropySource
	} else { // Default: use the OS-wide global, shared instance of a CS-RNG.
		NistPrng.entropySource = crand.Reader
	}
	// 6&7. (status, entropy_input) = Get_entropy_input (security_strength, min_length,
	// max_length, prediction_resistance_request).
	// .    IF (status != SUCCESS)--> return (status, Invalid).
	switch entropyInputLen := len(entropyInput); {
	case entropyInputLen == 0: // Sample entropyInput if not provided
		entropyInput = make([]byte, securityStrength)
		if _, err := NistPrng.entropySource.Read(entropyInput); err != nil {
			return nil, errs.WrapRandomSampleFailed(err, "cannot sample entropyInput")
		}
	case entropyInputLen < securityStrength:
		return nil, errs.NewInvalidLength("entropyInput too small")
	case entropyInputLen > maxLength:
		return nil, errs.NewInvalidLength("entropyInput too large")
	}
	// 8. Obtain a nonce if not provided.
	switch nonceLen := len(nonce); {
	case nonceLen == 0: // Sample nonce if not provided
		nonce = make([]byte, securityStrength/2)
		if _, err = NistPrng.entropySource.Read(nonce); err != nil {
			return nil, errs.WrapRandomSampleFailed(err, "cannot sample nonce")
		}
	case nonceLen < securityStrength/2:
		return nil, errs.NewInvalidLength("nonce too small")
	}
	// 9. initial_working_state = Instantiate_algorithm(entropy_input, nonce,
	// personalization_string, security_strength).
	NistPrng.ctrDrbg = NewCtrDRBG(keySize)
	if err = NistPrng.ctrDrbg.Instantiate(entropyInput, nonce, personalization); err != nil {
		return nil, errs.WrapFailed(err, "cannot instantiate the internal ctr prng")
	}
	return NistPrng, nil
}

// Reseed will reseed the PRNG as specified in SP-800-90A section 9.2. It uses
// truly random inputs as seed material:
//
//	A) A fresh entropyInput of at least keySize Bytes. If not provided, sampled from entropySource.
//	B) An optional additionalInput, acting as an additional personalization string (see `NewPRNG`). Can be left empty.
//
// The entropyInput length must be at least keySize Bytes .
func (prg *PrngNist) Reseed(entropyInput, additionalInput []byte) (err error) {
	// 1. Using state_handle, obtain the current internal state. --> implicit.
	// 2. IF prediction_resistance_flag... --> Skipped, implicit.
	// 3. IF len(additional_input) > max_additional_input_length: return EEROR_FLAG
	if int64(len(additionalInput)) > maxLength {
		return errs.NewInvalidLength("additionalInput too large")
	}
	// 4&5. (status, entropy_input) = Get_entropy_input (security_strength, min_length,
	// max_length, prediction_resistance_request).
	// .    IF (status != SUCCESS)--> return (status, Invalid).
	switch entropyInputLen := len(entropyInput); {
	case entropyInputLen == 0: // Sample entropyInput if not provided
		entropyInput = make([]byte, prg.SecurityStrength())
		if prg.entropySource == nil {
			return errs.NewInvalidArgument("cannot reseed without external entropy")
		}
		if _, err := prg.entropySource.Read(entropyInput); err != nil {
			return errs.WrapRandomSampleFailed(err, "cannot sample entropyInput")
		}
	case entropyInputLen < prg.SecurityStrength():
		return errs.NewInvalidLength("entropyInput too small")
	case entropyInputLen > maxLength:
		return errs.NewInvalidLength("entropyInput too large")
	}
	// 6. new_working_state = Reseed_algorithm(working_state, entropy_input,
	// additional_input).
	if err = prg.ctrDrbg.Reseed(entropyInput, additionalInput); err != nil {
		return errs.WrapFailed(err, "cannot reseed the prng")
	}
	return nil
}

// Generate samples `len(buffer)` random bytes and stores them in `buffer`,
// as specified in SP-800-90A section 9.3. The buffer length must be at most
//
// If the PRNG needs reseeding, it will be carried out automatically if the prng
// was initialised with an `entropySource`, raising an error otherwise.
func (prg *PrngNist) Generate(buffer, additionalInput []byte) error {
	if len(buffer) == 0 {
		return errs.NewInvalidLength("buffer must be non-empty")
	}
	// 1. Using state_handle... --> implicit.
	// 2. IF (requested_number_of_bits > max_number_of_bits_per_request):
	// .	return (ERROR_FLAG, Nil).
	if len(buffer) > maxNumberOfBytesRequest {
		return errs.NewInvalidLength("too many bytes requested")
	}
	// 3. IF requested_security_strength > security_strength... --> implicit.
	// 4. IF (length of the additional_input > max_additional_input_length):
	// .	return (ERROR_FLAG, Nil).
	if int64(len(additionalInput)) > maxLength {
		return errs.NewInvalidLength("additionalInput too large")
	}
	// 5. If prediction_resistance_request is set... --> implicit.
	// 6. Clear the reseed_required_flag.
	var reseedRequired bool
dataGeneration:
	// 8. (status, pseudorandom_bits, new_working_state) = Generate_algorithm(
	// working_state, requested_number_of_bits, additional_input).
	switch err := prg.ctrDrbg.Generate(buffer, additionalInput); {
	case errs.IsRandomSampleFailed(err) && prg.entropySource != nil:
		// 9. If status indicates that a reseed is required, then
		// 9.1. Set the reseed_required_flag.
		// 9.2. If the prediction_resistance_flag... --> implicit.
		// 9.3. Go to step 7.
		reseedRequired = true
	case err != nil:
		return errs.WrapRandomSampleFailed(err, "cannot generate random data")
	default: // no errors
		reseedRequired = false
	}
	// 7. If reseed_required_flag is set, then reseed.
	if reseedRequired {
		// 7.1. status = Reseed_function(state_handle, ..., additional_input).
		if err := prg.Reseed(nil, additionalInput); err != nil {
			// 7.2. IF (status != SUCCESS), then return (status, Nil).
			return errs.WrapRandomSampleFailed(err, "cannot reseed")
		}
		// 7.3 Using state_handle... --> implicit.
		// 7.4. additional_input = Nil.
		additionalInput = nil
		// 7.5. Clear the reseed_required_flag --> implicit.
		goto dataGeneration
	}
	return nil
}

// Read will sample `len(buffer)` random bytes and store them in `buffer`.
//
// It splits the buffer in chunks of `maxNumberOfBytesRequest` bytes, and calls
// `Generate` on each chunk. If the PRNG needs reseeding, it will be carried out
// automatically if the prng was initialised with an `entropySource`, raising an
// error otherwise.
func (prg *PrngNist) Read(buffer []byte) (n int, err error) {
	numRequests := utils.CeilDiv(len(buffer), maxNumberOfBytesRequest)
	for i := 0; i < numRequests; i++ {
		end := utils.Min((i+1)*maxNumberOfBytesRequest, len(buffer))
		requestBuffer := buffer[i*maxNumberOfBytesRequest : end]
		if err := prg.Generate(requestBuffer, nil); err != nil {
			return n, errs.WrapRandomSampleFailed(err, "Could not generate random bits")
		}
	}
	return len(buffer), nil
}

// SecurityStrength returns the computational security parameter of this prng (in Bytes).
// Equates to the length of the key used in the internal AES block cipher.
func (prg *PrngNist) SecurityStrength() int {
	return prg.ctrDrbg.keySize
}

// Seed re-instantiates the PRNG with a new seed (`entropyInput`) and salt (`nonce`).
func (prg *PrngNist) Seed(entropyInput, nonce []byte) (err error) {
	// Check seed and nonce
	switch entropyInputLen := len(entropyInput); {
	case entropyInputLen < prg.SecurityStrength():
		return errs.NewInvalidLength("entropyInput too small")
	case entropyInputLen > maxLength:
		return errs.NewInvalidLength("entropyInput too large")
	}
	switch nonceLen := len(nonce); {
	case nonceLen == 0: // Sample nonce if not provided
		nonce = make([]byte, prg.SecurityStrength()/2)
		if _, err = prg.entropySource.Read(nonce); err != nil {
			return errs.WrapRandomSampleFailed(err, "cannot sample nonce")
		}
	case nonceLen < prg.SecurityStrength()/2:
		return errs.NewInvalidLength("nonce too small")
	}
	// Re-instantiate
	if err = prg.ctrDrbg.Instantiate(entropyInput, nonce, nil); err != nil {
		return errs.WrapFailed(err, "cannot instantiate the internal ctr prng")
	}
	return nil
}

// New returns a new NistPRNG with the provided seed and salt.
func (prg *PrngNist) New(seed, salt []byte) (csprng.CSPRNG, error) {
	return NewNistPRNG(prg.SecurityStrength(), prg.entropySource, seed, salt, nil)
}

// Clone returns a copy of this NistPRNG.
func (prg *PrngNist) Clone() csprng.CSPRNG {
	return &PrngNist{
		entropySource: prg.entropySource,
		ctrDrbg:       prg.ctrDrbg.Clone(),
	}
}
