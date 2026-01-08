# OR Composition

Composes sigma protocols to prove knowledge of a witness for at least one of n statements.

## Security

- Witness indistinguishability: verifier cannot determine which branch the prover knows
- Uses XOR technique: challenges for all branches XOR to equal verifier's challenge

## Usage

```go
// n-way OR composition (same protocol type)
orProtocol, _ := sigor.Compose(schnorrProtocol, 3, prng)
statement := sigor.ComposeStatements(x0, x1, x2)
witness := sigor.ComposeWitnesses(w0, w1, w2) // only one needs to be valid

// Binary OR composition (different protocol types)
orProtocol := sigor.CartesianCompose(protocol0, protocol1, prng)
```

## How It Works

The prover runs the real protocol for the branch they know, and simulates the other branches. The XOR constraint ensures at least one branch must be honestly computed.

## Reference

[Sch25]: https://berry.win.tue.nl/CryptographicProtocols/LectureNotes.pdf
