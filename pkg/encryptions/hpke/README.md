# Hybrid Public Key Encryption (RFC 9180)

This package implements a scheme for hybrid public key encryption as per [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html).
For an ECC-based encryption mechanism where threshold decryption is not needed, this package should be used.

This scheme provides a variant of public key encryption of arbitrary-sized plaintexts for a recipient public key.
It also includes three authenticated variants, including one that authenticates possession of a pre-shared key
and two optional ones that authenticate possession of a key encapsulation mechanism (KEM) private key.
HPKE works for any combination of an asymmetric KEM, key derivation function (KDF), and authenticated encryption 
with additional data (AEAD) encryption function. Some authenticated variants may not be supported by all KEMs.
We provide instantiations of the scheme using widely used and efficient primitives,
such as Elliptic Curve Diffie-Hellman (ECDH) key agreement, HMAC-based key derivation function (HKDF), and SHA2.
