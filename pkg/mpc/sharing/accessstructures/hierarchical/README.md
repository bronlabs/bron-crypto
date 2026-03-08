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

MSP induction and maximal unqualified set enumeration are not yet implemented.

## Reference

- T. Tassa, "Hierarchical Threshold Secret Sharing." J Cryptology 20, 237-264 (2007).
