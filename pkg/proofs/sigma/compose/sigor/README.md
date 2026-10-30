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
witness := sigor.NewWitness(w0) // only one needs to be valid

// Binary OR composition (different protocol types)
orProtocol := sigor.CartesianCompose(protocol0, protocol1, prng)
```

## How It Works

The prover runs the real protocol for the branch they know, and simulates the other branches. The XOR constraint ensures at least one branch must be honestly computed.

## Special soundness

`SpecialSoundness()` of the composition is $(k - 1)^n + 1$ for $n$ branches of a $k$-special sound protocol, and $(k_0 - 1)(k_1 - 1) + 1$ for the binary composition. Accepting OR transcripts with the same commitments and distinct challenges have distinct tuples of branch challenges, so with that many transcripts some branch must see $k$ distinct challenges and its witness can be extracted; with fewer, a prover holding $k - 1$ simulated transcripts per branch can assemble them all without any witness. For 2-special sound branches the composition is 2-special sound, and strongly so when the branches have unique responses, which is what `compiler/randfischlin` requires. The non-interactive compilers read this value to size their parameters, so composing branches with $k > 2$ (e.g. `dlog/batch_schnorr`) makes their proofs correspondingly more expensive.

`CartesianCompose` requires both branches to have the same challenge length. A branch that read only a prefix of the shared challenge would leave the remaining bytes free for the prover, giving it accepting transcripts that differ only in bytes no branch depends on, which breaks special soundness.

## Reference

[Sch25]: https://berry.win.tue.nl/CryptographicProtocols/LectureNotes.pdf
