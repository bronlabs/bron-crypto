# Zero-Knowledge Compiler

Interactive 5-round protocol that compiles sigma protocols into zero-knowledge proofs with commit-then-open challenge generation.

## Protocol Rounds

| Round | Party | Action |
| ------- | ------- | -------- |
| 1 | Verifier | Commit to random challenge |
| 2 | Prover | Send sigma commitment |
| 3 | Verifier | Open challenge commitment |
| 4 | Prover | Verify opening, send response |
| 5 | Verifier | Verify sigma protocol |

## Usage

```go
prover, _ := zk.NewProver(sessionId, transcript, sigmaProtocol, statement, witness)
verifier, _ := zk.NewVerifier(sessionId, transcript, sigmaProtocol, statement, prng)

commitment, _ := verifier.Round1()
proverComm, _ := prover.Round2(commitment)
challenge, witness, _ := verifier.Round3(proverComm)
response, _ := prover.Round4(challenge, witness)
err := verifier.Verify(response)
```

## When to Use

Use when interactive communication is available and you need true zero-knowledge (not just honest-verifier ZK).

## Reference

[HL10]: https://link.springer.com/book/10.1007/978-3-642-14303-8

See chapter 6.3 "Proof of Knowledge" in Hazay & Lindell, "Efficient Secure Two-Party Protocols"
