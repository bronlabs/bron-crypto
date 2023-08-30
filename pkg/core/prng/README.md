# PRNG package
This package implements a Cryptographically-secure pseudo-random number generator 
(CS-PRNG) following the NIST specification [SP 800-90A Rev. 1][1]. 
The implementation is based on the [AES-CTR-DRBG][2]  Deterministic Random Bit Generator (DRBG) definition of said specification, based on AES (AES128 or AES256) as block cipher in counter mode.

This implementation is defined to:
- Support the block-cipher-based derivation function specified in [SP 800-90A Rev. 1] in order to derive the seed material of the right size from the provided inputs.
- Not support prediction resistance (e.g., doesn't require a new reseed after each generation, but only after a certain amount of bytes have been generated).

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
This package was validated using the official [NIST CAVP test vectors][3] as part of the [Deterministic Random Bit Generators Validation System (DRBGVS)][4]. The test vectors are included verbatim (directly extracted from the provided [.zip file][5]) in the `drbgtestvectors` folder, and a test suite is provided in `prng_test.go` with utilities in the `nist_validation_utils.go`.

## References

- [SP 800-90A Rev. 1][1], NIST Special Publication 800-90A (Revision 1) Recommendation for Random Number Generation Using Deterministic Random Bit Generators.
- [AES-CTR-DRBG][2], NIST Special Publication 800-90A (Revision 1) Recommendation for Random Number Generation Using Deterministic Random Bit Generators, Section 10.2.
- [DRBGVS][4], NIST Cryptographic Algorithm Validation Program (CAVP) - Deterministic Random Bit Generators Validation System.
- [DRBGVS Test Vectors][5], NIST Cryptographic Algorithm Validation Program (CAVP) - Deterministic Random Bit Generators Validation System - Test Vectors.

[1]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf
[2]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf#page=57
[3]: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/random-number-generators
[4]: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/DRBGVS.pdf
[5]: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip
