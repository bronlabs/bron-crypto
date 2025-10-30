# `nist` package
This package implements a Cryptographically-secure pseudo-random number generator 
(CS-PRNG) following the NIST specification [SP 800-90A Rev. 1][1]. 
The implementation is based on the [AES-CTR-DRBG][2] Deterministic Random Bit Generator (DRBG) definition of said specification, based on AES (AES128 or AES256) as block cipher in counter mode.

This implementation is defined to:
- Support the block-cipher-based derivation function specified in [SP 800-90A Rev. 1] in order to derive the seed material of the right size from the provided inputs.
- Not support prediction resistance (e.g., doesn't require a new reseed after each generation, but only after a certain amount of requests have been made).

Note that this implementation set lower bounds than the standard for:
- The maximum number of bits per requests between reseeds (`max_number_of_bits_per_request`). While the standard allows to generate up to 2^{19} bits per requests, several analyses suggest to set to further limit the amount of data that can be requested in a single call[3], [4], [5]. Here it is set to 2^{10} bytes (i.e. 2^{13} bits) as [done in mbed TLS](https://github.com/ARMmbed/mbed-crypto/blob/development/include/mbedtls/ctr_drbg.h#L130). 
- The maximum number of requests between reseeds (`reseed_interval`). As for `max_number_of_bits_per_request`, the same analyses[3], [4], [5] recommend to reseed more frequently than every 2^{48} requests. This implementation enforces reseeding after 2^{12} calls.

## Initialisation
To create a new PRNG instance, use the `NewAesPRNG(entropySource, entropyInput, nonce, personalization)` function. It takes four arguments:
- `entropySource` is the source of entropy used to seed the PRNG. It will be used to sample the initial seed in the absence of `entropyInput`, and to reseed the PRNG with fresh seeds when necessary. Defaults to `crypto/rand.Reader`.
- `entropyInput` is the **secret** initial seed of the PRNG, must be at least `keySize` Bytes (16B for AES128 or 32B for AES256) of true randomness. If `nil`, the PRNG will be seeded with fresh entropy from `entropySource`.
- `nonce` is a **public** random value used only once to seed the PRNG, must be at least `keySize/2` Bytes (8B for AES128 or 16B for AES256) or repeat with that same probability. If `nil`, the nonce is sampled from `entropySource`.
- `personalization (optional)` is an optional string used to "salt" the initial state. It has no length constraints and it need not be random.
```go
NewAesPRNG
```
## Usage
The package provides a unified interface, `PRNG`, implementing three methods:
1. `Reseed(entropyInput, additionalInput)` to reseed the PRNG with:
    - `entropyInput`, a fresh seed with true randomness. If not provided (`nil`), the seed is sampled from `entropySource`.
    - `additionalInput (optional)`, an optional string used to "salt" the reseeding process. It has no length constraints and it need not be random.
2. `Generate(buffer, additionalInput)` to generate random bytes, where:
    - `buffer` is the buffer to fill with random bytes.
    - `additionalInput (optional)` is an optional string used to "salt" the generation process. It has no length constraints and it need not be random. It will call `Reseed()` if the PRNG needs to be reseeded, raising an error if no `entropySource` was provided.
3. `Read()` to generate random bytes (following the `io.Reader` interface).

## Testing
This package was validated using the official [NIST CAVP test vectors][6] as part of the [Deterministic Random Bit Generators Validation System (DRBGVS)][7]. The test vectors are included verbatim (directly extracted from the provided [.zip file][8]) in the `drbgtestvectors` folder, and a test suite is provided in `prng_test.go` with utilities in the `nist_validation_utils.go`.

## References
[1]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf (NIST Special Publication 800-90A (Revision 1) Recommendation for Random Number Generation Using Deterministic Random Bit Generators)
[2]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf#page=57 (NIST Special Publication 800-90A (Revision 1) Recommendation for Random Number Generation Using Deterministic Random Bit Generators, Section 10.2)
[3]: https://eprint.iacr.org/2019/996.pdf (Pseudorandom Black Swans: Cache Attacks on CTR DRBG)
[4]: https://eprint.iacr.org/2018/349.pdf (An analysis of the NIST SP 800-90A Standard)
[5]: https://eprint.iacr.org/2020/619.pdf (Security Analysis of NIST CTR-DRBG)
[6]: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/random-number-generators (NIST Cryptographic Algorithm Validation Program - CAVP Testing: Random Number Generators)
[7]: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/DRBGVS.pdf (The NIST SP 800-90A Deterministic Random Bit Generator Validation System (DRBGVS))
[8]: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip (NIST Cryptographic Algorithm Validation Program (CAVP) - Deterministic Random Bit Generators Validation System - Test Vectors)
