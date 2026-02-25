# Tassa Secret Sharing

`pkg/threshold/sharing/scheme/tassa` implements a hierarchical secret sharing scheme over prime fields.

## Summary

- Access policy: `sharing.HierarchicalConjunctiveThresholdAccessStructure`
- Secret/share domain: prime field elements
- Dealer function: random polynomial with level-dependent derivatives used for share generation
- Reconstruction: solves a linear system derived from the qualified quorum

## Usage

```go
ac, err := sharing.NewHierarchicalConjunctiveThresholdAccessStructure(
    sharing.WithLevel(1, 1, 2),
    sharing.WithLevel(3, 3, 4, 5),
    sharing.WithLevel(5, 6, 7),
)
if err != nil {
    panic(err)
}

scheme, err := tassa.NewScheme(ac, field)
if err != nil {
    panic(err)
}

secret := tassa.NewSecret(field.FromUint64(42))
dealt, err := scheme.Deal(secret, prng)
if err != nil {
    panic(err)
}

recovered, err := scheme.Reconstruct(
    dealt.Shares().Get(1),
    dealt.Shares().Get(3),
    dealt.Shares().Get(4),
    dealt.Shares().Get(6),
    dealt.Shares().Get(7),
)
if err != nil {
    panic(err)
}

_ = recovered
```

## Spec (Pseudocode)

### Sharing

```text
Algorithm Sharing(ac, F, secret s, rng):
  Input:
    - ac = [(T1, L1), (T2, L2), ..., (Tm, Lm)]
      where Li is the set of shareholder IDs at level i
      and Ti is the cumulative threshold for levels 1..i
    - F = prime field
    - s = secret in F
    - rng = randomness source
  Output:
    - shares map ID -> F

  1. Set k <- Tm - 1.
  2. Sample f(x), a random polynomial over F of degree k such that f(0) = s.
  3. Set d <- 0.
  4. For each level (Ti, Li) in ac order:
     4.1 Set g(x) <- d-th derivative of f(x).
     4.2 For each id in Li, set shares[id] <- g(id).
     4.3 Set d <- Ti.
  5. Return shares.
```

### Reconstructing

```text
Algorithm Reconstruct(ac, F, quorum Q, shares):
  Input:
    - ac = hierarchical access structure
    - F = prime field
    - Q = distinct shareholder IDs from provided shares
    - shares = map ID -> F
  Output:
    - secret s in F

  1. Require Q is qualified under ac.
  2. Order Q increasingly: [i1, ..., in].
  3. Build an n x n matrix M with entries:
     3.1 Let rank(id) be the threshold of the previous level containing id.
     3.2 Let phi(t, i, j) = (d^j/dx^j x^t) evaluated at x = i.
     3.3 Set M[r, c] = phi(c, ir, rank(ir)).
  4. Compute d <- det(M); require d != 0.
  5. Set Y <- column vector [shares[i1], ..., shares[in]].
  6. Set M0 <- M with the first column replaced by Y.
  7. Compute d0 <- det(M0).
  8. Set s <- d0 / d.
  9. Return s.
```

## Reference

This implementation follows the hierarchical sharing construction and constraints from:

- G. Traverso, D. Demirel, J. Buchmann, *Dynamic and Verifiable Hierarchical Secret Sharing* ([IACR ePrint 2017/724](https://eprint.iacr.org/2017/724.pdf)).
- T. Tassa, Hierarchical Threshold Secret Sharing. ([J Cryptology 20, 237–264 (2007)](https://link.springer.com/article/10.1007/s00145-006-0334-8))
