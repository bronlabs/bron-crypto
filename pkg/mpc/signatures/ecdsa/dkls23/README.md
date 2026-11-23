# `dkls23`: Threshold ECDSA

This package implements the threshold ECDSA of
[DKLs23](https://eprint.iacr.org/2023/765), "Threshold ECDSA in Three Rounds". It
holds the types shared across the protocol: the key share `Shard`, built from a base
shard by `keygen`, and the `PartialSignature` each signer outputs. The protocols live in
the subpackages:

- `keygen`: the adapter from a distributed-key-generation shard to a DKLs23 `Shard`.
- `signing`: the signing-layer core of Protocol 3.6 and the cosigning and
  non-cosigning aggregators that turn partial signatures into an ECDSA signature,
  with two instantiations: `signing/softspoken`, four rounds over the SoftSpokenOT
  extension on MRR21 base OTs, and `signing/mrr21`, the paper's three rounds directly
  on MRR21 base OTs without an extension. The READMEs describe the rounds, the 2026
  follow-up fixes and the references.
