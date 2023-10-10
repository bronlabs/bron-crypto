# Threshold BLS

This package implements threshold BLS using [Boldyreva02](https://eprint.iacr.org/2002/118.pdf). The output signature is verifiable with [official spec](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html).


The threshold implementation supports both variants of the BLS signatures:

- **Short public keys, long signatures**: Signatures are longer and slower to create, verify, and aggregate but public keys are small and fast to aggregate. Used when signing and verification operations not computed as often or for minimizing storage or bandwidth for public keys.
- **Short signatures, long public keys**: Signatures are short and fast to create, verify, and aggregate but public keys are bigger and slower to aggregate. Used when signing and verification operations are computed often or for minimizing storage or bandwidth for signatures.

User will have to specify G1 as the key/signature subgroup for the public key/signature to be short.

The output signature can be incorporated in a multisignature protocol requiring the `basic` rogue key prevention scheme.


## Remark

The protocol described in the paper is honest majority as robustness is achieved (which means t < n/2 is an optimal result). The restriction is imposed by the DKG (refer to proof in Appendix A), and we already have the DKG modified not to have robustness. We therefore use this protocol in dishonest majority setting.
The alternative is to use [GLOW20](https://eprint.iacr.org/2020/096.pdf) whose signing portion is essentially the same protocol, except it avoids the pairing overhead during verification of partial signatures. They do however require keys to live in G1.
