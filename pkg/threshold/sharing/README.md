# Secret Sharing

`pkg/threshold/sharing` provides core interfaces and access-structure primitives used by secret sharing schemes in this repository.

## Access Structures

The package includes monotone access structures that decide whether a set of shareholder IDs can reconstruct a secret:

- `ThresholdAccessStructure`: classic `(t, n)` threshold policy.
- `UnanimityAccessStructure`: `n-of-n` policy.
- `CNFAccessStructure`: policy encoded by maximal unqualified sets.
- `DNFAccessStructure`: policy encoded by minimal qualified sets.
- `HierarchicalConjunctiveThresholdAccessStructure`: multi-level policy with cumulative thresholds.

### Hierarchical Conjunctive Threshold Policy

A hierarchical policy is defined as ordered levels. Each level introduces a disjoint set of shareholders and a cumulative threshold that must be met by parties selected from all levels up to that point.

Example policy:

```go
h, err := sharing.NewHierarchicalConjunctiveThresholdAccessStructure(
    sharing.WithLevel(1, 2),
    sharing.WithLevel(3, 4, 5),
    sharing.WithLevel(5, 6, 7),
)
```

Interpretation:

- From level 1 parties (`{1,2}`), at least `1` must participate.
- From levels 1-2 parties (`{1,2,3,4,5}`), at least `3` must participate.
- From levels 1-3 parties (`{1,2,3,4,5,6,7}`), at least `5` must participate.

This implementation follows a hierarchical threshold-sharing model based on:

- H. Talaat and A. M. Youssef, *Hierarchical Secret Sharing with Multi-level Access Structure* ([IACR ePrint 2017/724](https://eprint.iacr.org/2017/724.pdf)).

## Related Scheme Implementations

Concrete schemes live in subpackages:

- `scheme/shamir`
- `scheme/feldman`
- `scheme/pedersen`
- `scheme/additive`
- `scheme/isn`
- `scheme/tassa`
