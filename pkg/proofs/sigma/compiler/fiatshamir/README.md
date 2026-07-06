# Fiat-Shamir Transform

Compiles interactive sigma protocols into non-interactive proofs using hash-based challenge derivation.

Uses strong Fiat-Shamir which includes the statement in the challenge and hash chaining for unambiguous transcript hashing.

Internally, it uses ZKModule from CGGMP21 Figure 3 such that the Commit operation occurs immediately before Prove.

## Security

- sequentially composable security in the random oracle model.

## Usage

```go
nizk, _ := fiatshamir.NewCompiler(sigmaProtocol)
prover, _ := nizk.NewProver(ctx)
proof, _ := prover.Prove(statement, witness)
```

## Proof Structure

Carries the prover's commitment (a), the challenge (e), and the response (z). On verification the challenge is recomputed from the transcript hash and checked against the e in the proof before the sigma relation is verified.

## Reference

<!-- paper: docs/papers/Fiat-Shamir.pdf -->
- [FS86](https://link.springer.com/content/pdf/10.1007/3-540-47721-7_12.pdf)
<!-- paper: docs/papers/bonehshoup.pdf [section 20.3.3] -->
- [Dan Boneh and Victor Shoup; A Graduate Course in Applied Cryptography, version 0.6, section 20.3.3](https://toc.cryptobook.us/)
<!-- paper: docs/papers/2021-060_20241021_172019.pdf [section 3.4.1 and figure 3] -->
- [CGGMP21, Section 3.4.1 and Figure 3](https://eprint.iacr.org/2021/060.pdf)
