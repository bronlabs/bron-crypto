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

## Reference

This implementation follows the hierarchical sharing construction and constraints from:

- H. Talaat and A. M. Youssef, *Hierarchical Secret Sharing with Multi-level Access Structure* ([IACR ePrint 2017/724](https://eprint.iacr.org/2017/724.pdf)).
