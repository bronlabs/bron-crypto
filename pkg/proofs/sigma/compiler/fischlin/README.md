# Fischlin Transform

Compiles interactive sigma protocols into UC-secure non-interactive proofs.

## Security

- Universally composable (UC) security
- Stronger than Fiat-Shamir; safe for concurrent composition
- Parameters (rho, b, t) computed from protocol's special soundness

## Usage

```go
nizk, _ := fischlin.NewCompiler(sigmaProtocol, prng)
prover, _ := nizk.NewProver(sessionId, transcript)
proof, _ := prover.Prove(statement, witness)
```

## How It Works

Runs rho parallel executions, searching for challenge/response pairs that hash to zero. This provides simulation-extractability required for UC security.

## Reference

[CL24]: https://eprint.iacr.org/2024/526.pdf

Chen & Lindell, "Optimising and Implementing Fischlin's Transform for UC-Secure Zero-Knowledge"
