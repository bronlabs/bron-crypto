# `csprng`: Criptographically-Secure Pseudo-Random Number Generators
This package implements a common interface for multiple CS-PRNGs provided by this library.
These include:
- `chacha20`: Chacha20 stream cipher used as a CS-PRNG \[1\][1].
- `nist`: NIST SP 800-90A Rev. 1 compliant CS-PRNG based on AES-CTR-DRBG, using AES128 or AES256 as block cipher \[2\][2].
- `tmmohash`: AES-based Hashing as a CS-PRNG, using AES block cipher twice as an ideal permutation \[3\][3].

**IMPORTANT!** `chacha20` and `tmmohash` should only be used in scenarios where neither automatic reseeding nor key derivation are required. For this, there are two main conditions:
1. The seed material should be properly protected (e.g., as the output of a hash function or a KDF) before being passed to the PRNG.
2. The PRNG should be either be used a limited number of times or reseeded manually when necessary (e.g., after a certain amount of bytes have been generated).

For all other scenarios, use `nist` instead or include a KDF and automatic reseeding in your implementation.

## Usage
Each package has its own `New...` function to create a new PRNG instance, and implements the `CSPRNG` interface that includes a `New` function.
All prngs should be initialised with a fresh seed and a nonce (`salt`), and can be reseeded with fresh entropy when necessary. Sampling bytes is done via the `Read()` method, or by calling `Generate()` if you want to provide an additional `salt` to the generation process.

In general, all these PRNGs can be used as Pseudo-Random Functions (PRFs), in cases such as:
- As `PRG` for the expansion of the Oblivious Transfer (OT) keys in the OT extension protocol (see `pkg/ot/extension`).
- As a seeded PRNG for the synchronized states in pseudo-random zero-share sampling PRZS (see `sharing/zero/przs`) inside a single session.
- As a seeded PRNG for the `ExtractBytes` method of the transcript (see `pkg/transcripts/hagrid`), using the transcript state as seed to generate randomness.

Only `nist` can be used as a drop-in replacement of `crypto/rand`, providing hollistic "non-seeded" random number generation as long as it can still sample `crypto/rand` (or an equivalent entropy source) for very occasional reseeding.


## References
\[1\] ChaCha20 and Poly1305 for IETF Protocols. June 2018. https://datatracker.ietf.org/doc/html/rfc8439

\[2\] NIST Special Publication 800-90A (Revision 1) Recommendation for Random Number Generation Using Deterministic Random Bit Generators. https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf

\[3\] Efficient and Secure Multiparty Computation from Fixed-Key Block Ciphers. C. Guo, J Katz, X. Wang. 2019. https://eprint.iacr.org/2019/074.pdf    

[1]: "https://datatracker.ietf.org/doc/html/rfc8439"
[2]: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf"
[3]: "https://eprint.iacr.org/2019/074.pdf"