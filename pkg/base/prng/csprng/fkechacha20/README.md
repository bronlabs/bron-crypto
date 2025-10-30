# `chacha20` as a CS-PRNG
This package implements a Cryptographically-secure pseudo-random number generator
(CS-PRNG) based on a fork of the ChaCha20 stream cipher [1] provided by the standard library
in `golang.org/x/crypto/chacha20`. We initialise a ChaCha20 cipher with the provided
key, and then use the cipher to repeatedly XOR the same arbitrary plaintext 
(we use a slice of zeros) in stream mode, using the resulting variable-length ciphertext
as the output of the PRNG.

## PRNG properties
- _SecurityStrength_: The ChaCha20 stream cipher is a secure symmetric encryption algorithm with 256-bit keys.
- _SeedSize_: The key size is always 32 bytes. Nonces can have 12 or 24 bytes. Higher nonces are trimmed.
- _AutomaticReseeding_: Yes, we reseed the key with the PRNG itself.
- _KeyDerivationFunction_: Only for the initial key if small nonce is provided, using `HChacha20`.


## Fast-key erasure and long-sequence optimisation

This PRNG uses the fast-key erasure technique described in [2]. In short, the key is refreshed at each PRNG call to provide forward secrecy: if the entire PRNG state is compromised, it will not reveal the random sequences previously generated.

[1]: https://datatracker.ietf.org/doc/html/rfc8439 ("RFC 8439 - ChaCha20 and Poly1305 for IETF Protocols")
[2]: https://blog.cr.yp.to/20170723-random.html ("Fast-key-erasure random-number generators")