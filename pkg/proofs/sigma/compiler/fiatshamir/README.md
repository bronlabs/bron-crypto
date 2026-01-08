# Fiat-Shamir Transform

Compiles interactive sigma protocols into non-interactive proofs using hash-based challenge derivation.

## Security

- sequentially composable security in the random oracle model.

## Usage

```go
nizk, _ := fiatshamir.NewCompiler(sigmaProtocol)
prover, _ := nizk.NewProver(sessionId, transcript)
proof, _ := prover.Prove(statement, witness)
```

## Proof Structure

Contains the prover's commitment (a) and response (z). The verifier recomputes the challenge from the transcript hash.

## Reference

[FS86]: https://link.springer.com/content/pdf/10.1007/3-540-47721-7_12.pdf

Uses strong Fiat-Shamir which includes the statement in the challenge and hash chaining for unambiguous transcript hashing.
