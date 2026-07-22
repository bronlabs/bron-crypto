# lindell17/keygen/trusted_dealer

This package implements Lindell17 key generation with a trusted dealer for an
arbitrary monotone access structure.

The dealer encrypts every raw MSP share component under its owner's Paillier
public key. A shareholder's shard retains the encrypted component vector and
public key of each peer with which it forms a qualified two-party quorum.
MSP-to-additive conversion and pseudorandom zero-share refresh happen for the
selected quorum during signing.

Unlike the DKG package, this setup does not attach LP or LPDL proofs to the
encrypted components. It therefore assumes that the dealer honestly generates
the base shares, Paillier keys, and ciphertexts, and then erases its copies of
all secret material.

Production callers must request Paillier moduli of at least 3072 bits
(`base.IFCKeyLength`) and supply a cryptographically secure `io.Reader`, such as
`crypto/rand.Reader`.
