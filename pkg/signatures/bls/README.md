# BLS Signatures

BLS is a digital signature scheme with aggregation properties. Given set of signatures (signature_1, ..., signature_n) anyone can produce an aggregated signature. Aggregation can also be done on secret keys and public keys. Furthermore, the BLS signature scheme is deterministic, non-malleable, and efficient. Its simplicity and cryptographic properties allows it to be useful in a variety of use-cases, specifically when minimal storage space or bandwidth are required.

This implements [draft-irtf-cfrg-bls-signature-05](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html)

## Properties

We support both variants of the BLS signatures:

- **Short public keys, long signatures**: Signatures are longer and slower to create, verify, and aggregate but public keys are small and fast to aggregate. Used when signing and verification operations not computed as often or for minimizing storage or bandwidth for public keys.
- **Short signatures, long public keys**: Signatures are short and fast to create, verify, and aggregate but public keys are bigger and slower to aggregate. Used when signing and verification operations are computed often or for minimizing storage or bandwidth for signatures.

User will have to specify G1 as the key/signature subgroup for the public key/signature to be short.

Furthermore, we support the 3 common schemes for rogue key attack prevention:
1. Basic: Requiring all messages to be unique.
2. Message Augmentation: Prepends public key of the signer to the message thereby making the messages unique.
3. Proof of Possession: A signature of the public key (= proof of possession of secret key) is accompanied with every signature.

It contains the regular verifier, as well as the [aggregate verifier](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-1-4.3)

> A collection of signatures (signature_1, ..., signature_n) can be aggregated into a single signature. Moreover, the aggregate signature can be verified using only n+1 pairings (as opposed to 2n pairings, when verifying n signatures separately).

If the Rogue key prevention scheme is POP, then we can do a faster variant of aggregate verification, which essentially aggregates all of the public keys and uses the simple verifier.

## Differences with Spec

- Our verifier is different from the spec in that it is optimized by using a trick explained [here](https://hackmd.io/@benjaminion/bls12-381#Final-exponentiation).
