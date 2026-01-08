# AND Composition

Composes sigma protocols to prove knowledge of witnesses for all n statements simultaneously.

## Security

- Same challenge used for all sub-protocols
- Prover must know valid witnesses for every statement

## Usage

```go
// n-way AND composition (same protocol type)
andProtocol, _ := sigand.Compose(schnorrProtocol, 3)
statement := sigand.ComposeStatements(x0, x1, x2)
witness := sigand.ComposeWitnesses(w0, w1, w2) // all must be valid

// Binary AND composition (different protocol types)
andProtocol := sigand.CartesianCompose(protocol0, protocol1)
```

## How It Works

All branches receive the same verifier challenge and compute responses in parallel. Verification checks that every branch's transcript is accepting.

## Reference

[Sch25]: https://berry.win.tue.nl/CryptographicProtocols/LectureNotes.pdf
