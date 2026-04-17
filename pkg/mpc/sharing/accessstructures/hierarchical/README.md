# Hierarchical Conjunctive Threshold Access Structure

Implements hierarchical access structures with ordered levels and strictly increasing cumulative thresholds.

## Overview

Shareholders are partitioned into ordered levels. A coalition is qualified if, at every level, the cumulative number of members from that level and all preceding levels meets the level's threshold.

## Usage

```go
ac, err := hierarchical.NewHierarchicalConjunctiveThresholdAccessStructure(
    hierarchical.WithLevel(1, 1, 2),       // level 1: cumulative threshold 1, parties {1, 2}
    hierarchical.WithLevel(3, 3, 4, 5),    // level 2: cumulative threshold 3, parties {3, 4, 5}
    hierarchical.WithLevel(5, 6, 7),       // level 3: cumulative threshold 5, parties {6, 7}
)
```

## Status

MSP induction is implemented via `InducedMSP`, which constructs a monotone span programme
from the Birkhoff-Vandermonde matrix. This enables hierarchical access structures to be
used with the KW MSP-based secret sharing scheme.

Maximal unqualified set enumeration is implemented via `MaximalUnqualifiedSetsIter`.
The current implementation is brute-force and intended only for small access structures.
It also requires shareholder IDs to lie in the range `1..64`.

## Reference

- T. Tassa, "Hierarchical Threshold Secret Sharing." J Cryptology 20, 237-264 (2007).
