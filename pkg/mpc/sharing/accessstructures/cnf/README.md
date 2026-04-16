# CNF Access Structure

Implements monotone access structures in conjunctive normal form, specified by maximal unqualified sets.

## Overview

A CNF access structure is defined by its maximal unqualified sets {T_1, ..., T_l}. A coalition is authorized if and only if it is not a subset of any T_j. Equivalently, each clause C_j = P \ T_j (the complement) must contain at least one member of the coalition.

## Usage

```go
// Direct construction from maximal unqualified sets
ac, err := cnf.NewCNFAccessStructure(unqualifiedSet1, unqualifiedSet2)

// Convert any Monotone access structure to CNF
cnfAC, err := cnf.ConvertToCNF(monotoneAccessStructure)
```

## MSP Induction

`InducedMSP` builds an MSP where each clause yields one block of rows (one per clause member). The number of columns equals the number of maximal unqualified sets.

## Reference

CNF is the canonical target representation for MSP induction of arbitrary linear access structures.
