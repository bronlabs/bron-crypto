# `chacha20` as a CS-PRNG
This package implements a Cryptographically-secure pseudo-random number generator
(CS-PRNG) based on the ChaCha20 stream cipher \[[1][1]\] provided by the standard library
in `golang.org/x/crypto/chacha20`. We initialise a ChaCha20 cipher with the provided
key, and then use the cipher to repeatedly encrypt the same arbitrary plaintext 
(we use a slice of zeros) in stream mode, using the resulting variable-length ciphertext
as the output of the PRNG.

**IMPORTANT!** This PRNG should only be used in scenarios where neither automatic reseeding nor key derivation are required. For this, there are two main conditions:
1. The seed material should be properly protected (e.g., as the output of a hash function or a KDF) before being passed to the PRNG.
2. The PRNG should be either be used a limited number of times or reseeded manually when necessary (e.g., after a certain amount of bytes have been generated).

## PRNG properties
- _SecurityStrength_: The ChaCha20 stream cipher is a secure symmetric encryption algorithm with 256-bit keys.
- _SeedSize_: The key size is always 32 bytes. Nonces can have 12 or 24 bytes. Higher nonces are trimmed.
- _AutomaticReseeding_: NO. The PRNG does not reseed automatically.
- _KeyDerivationFunction_: NO. The PRNG does not use a KDF. 

\[1\] ChaCha20 and Poly1305 for IETF Protocols. June 2018. https://datatracker.ietf.org/doc/html/rfc8439

[1]: "https://datatracker.ietf.org/doc/html/rfc8439"
