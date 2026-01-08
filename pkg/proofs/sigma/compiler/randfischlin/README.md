# Randomised Fischlin Transform

A variant of Fischlin's transform using fixed parameters and random challenge sampling.

## Security

- UC-secure like standard Fischlin

## Parameters

| Param | Value | Description |
|-------|-------|-------------|
| Lambda | 128 | Security parameter |
| L | 8 | Hash output bits |
| R | 16 | Parallel repetitions |
| T | 56 | Challenge sampling bound |

## Usage

```go
nizk, _ := randfischlin.NewCompiler(sigmaProtocol, prng)
prover, _ := nizk.NewProver(sessionId, transcript)
proof, _ := prover.Prove(statement, witness)
```

## When to Use

Preferred over standard Fischlin when using OR composition, or anything else that needs quasi-unique response property.

## Reference

[KS22]: https://eprint.iacr.org/2022/393.pdf (Fig. 9)

The statement is included in what needs to be hashed.
