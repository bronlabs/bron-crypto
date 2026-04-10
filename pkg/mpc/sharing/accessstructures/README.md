# Access Structures

Defines interfaces and dispatch logic for monotone access structures used in secret sharing.

## Overview

An access structure specifies which subsets of shareholders are authorized to reconstruct a shared secret. This package exposes one top-level interface:

- **Monotone**: monotone access structures with `IsQualified`, `Shareholders`, and `MaximalUnqualifiedSetsIter`

## Sub-packages

| Package | Access Structure | Description |
|---|---|---|
| `threshold` | (t,n) threshold | Any t-of-n shareholders can reconstruct |
| `unanimity` | n-of-n | All shareholders must participate |
| `cnf` | Conjunctive normal form | Specified by maximal unqualified sets |
| `hierarchical` | Hierarchical conjunctive threshold | Ordered levels with cumulative thresholds |
| `msp` | Monotone span programme | Linear-algebraic representation of access structures |
| `booleanexpr` | Generalized Boolean Expressions | Threshold/AND/OR-gate access trees |

## MSP Induction

`InducedMSP` dispatches to the most efficient MSP construction for known concrete types:

```go
mspProgram, err := accessstructures.InducedMSP(field, accessStructure)
```

For unknown `Monotone` implementations, it falls back to CNF conversion via `cnf.ConvertToCNF`.
