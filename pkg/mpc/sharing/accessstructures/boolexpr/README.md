# Threshold-Gate Boolean Expression Access Structure

Implements monotone access structures represented as a threshold-gate tree over shareholder attributes.

## Overview

Each leaf is a shareholder ID, and each internal node is a threshold gate. A coalition is qualified if it satisfies
the root gate. This representation covers ordinary threshold structures together 
with nested combinations of threshold, AND, and OR gates.

This package also implements MSP induction for threshold-gate trees using the construction of [Liu, Cao, and Wong][1]. 
The induced MSP has one row per leaf and can be used directly with the KW MSP-based secret sharing scheme.

## Usage

```go
ac, _ := boolexpr.NewThresholdGateAccessStructure(
    boolexpr.Threshold(2,
        boolexpr.And(
            boolexpr.ID(1),
            boolexpr.ID(2),
        ),
        boolexpr.Or(
            boolexpr.ID(3),
            boolexpr.ID(4),
        ),
        boolexpr.Threshold(2,
            boolexpr.ID(5),
            boolexpr.ID(6),
            boolexpr.ID(7),
        ),
    ),
)

qualified := ac.IsQualified(1, 2, 5, 6)
```

## MSP Induction

`InducedMSP` converts a threshold-gate tree into a monotone span programme following Algorithm 1 of [[1]][1]:

For a local `t`-of-`n` threshold gate, the construction uses the row vectors: $(1, i, i^2, ..., i^{t-1})$ for $i = 1, 2, ..., n$
over the ambient prime field. When a gate is expanded, its parent row prefix is copied into each child row 
and the extra `t-1` columns are filled with the corresponding powers of the child index. 
Repeating this from the root down yields an MSP with:
- one row per attribute leaf
- one column for the root secret plus the auxiliary columns introduced by threshold gates
- a row-to-shareholder map given by the leaf labels

## Spec

The implementation rewrites Algorithm 1 from the paper into the following operational form.

```text
Input:
  - a threshold-gate tree with root r
  - a prime field F

Output:
  - an MSP matrix M
  - a row labelling rho

Initialize:
  leaves := number of attribute leaves in the tree
  M := zero matrix of size leaves x leaves over F
  M[0,0] := 1
  L := array of length leaves
  L[0] := r
  m := 1    // number of active rows
  d := 1    // number of active columns

Loop:
  find the first index z in [0, m) such that L[z] is a threshold gate
  if no such z exists:
    stop

  let G := L[z]
  let m2 := number of children of G
  let d2 := threshold of G

  snapshot the current matrix prefix and active node list

  copy rows before z unchanged and extend them with zeros in the new columns

  for each child number c in [1, m2]:
    row := z + c - 1
    L[row] := G.children[c-1]
    copy the first d columns of the parent row z into row
    write c, c^2, ..., c^(d2-1) into the new columns

  shift the rows that originally followed z downward by m2 - 1 positions
  extend those shifted rows with zeros in the new columns

  update:
    m := m + m2 - 1
    d := d + d2 - 1

Finalize:
  truncate M to its first m rows and first d columns
  set rho[i] to the shareholder ID stored in leaf L[i]
```

This is exactly the tree-expansion strategy implemented in `convert`: each unresolved threshold gate
is replaced by its children, and each replacement appends the local threshold-gate columns
required by the paper's LSSS construction.

## Reference
- [Z. Liu, Z. Cao, and D. S. Wong, "Efficient Generation of Linear Secret Sharing Scheme Matrices from Threshold Access Trees," IACR ePrint 2010/374][1]

[1]: <https://eprint.iacr.org/2010/374.pdf>
