# ZK-Module

This package implements Figure 3 of CGGMP21, which specifies how to compile sigma protocols into non-interactive zero-knowledge proofs using a random oracle via the Fiat-Shamir heuristic.

Note that there is an additional "Commit" operation for generating the first message, kept separate from challenge derivation. This is useful for CGGMP21 to enable straight-line extraction without the forking lemma: the commitment can be absorbed into a larger session transcript before the challenge is fixed.

This is used internally in our fiatshamir compiler.

## Operations

| Step | Output | Notes |
| ------ | -------- | ------- |
| `Commit` | commitment `a`, secret state `s` | first sigma message; no challenge yet |
| `Prove` | proof `(a, e, z)` | absorbs `(statement, a)`, derives challenge `e` from the transcript hash, computes response `z` |
| `Verify` | accept/reject | re-derives `e'` from the transcript, rejects unless `e' == e`, then checks the sigma relation |

## Security

- Sound and zero-knowledge in the random oracle model, provided the underlying sigma protocol is honest-verifier zero-knowledge with a small enough soundness error (enforced by the fiatshamir compiler).
- The challenge binds the statement and commitment, so it must be re-derived on verification — never trusted from the proof alone.

## Reference

<!-- paper: docs/papers/2021-060_20241021_172019.pdf [section 3.4.1 and figure 3] -->
- [CGGMP21, Section 3.4.1 and Figure 3](https://eprint.iacr.org/2021/060.pdf)
<!-- paper: docs/papers/Fiat-Shamir.pdf -->
- [FS86](https://link.springer.com/content/pdf/10.1007/3-540-47721-7_12.pdf)
