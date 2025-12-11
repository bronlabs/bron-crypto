# cardinal

Package `cardinal` provides representations for cardinal numbers (cardinalities) used to express the size of algebraic structures such as groups, rings, and fields. 

## Overview

In cryptographic contexts, the cardinality of a structure may be known, unknown (hidden for security a la groups of unknown order), or infinite. This package provides three implementations of the `Cardinal` interface to handle these cases uniformly. We stress that the intention of this package is to provide clarity when dealing with cardinalities in a cryptographic context, NOT to implement a mathematically faithful version of cardinal arithmetics.

## Key Types

- **`Known`**: A cardinal with a concrete numeric value, stored as big-endian bytes.
- **`Unknown`**: Represents a cardinal whose value is intentionally hidden (e.g., the order of an RSA group without knowledge of the factorization).
- **`Infinite`**: Represents an infinite cardinality (e.g., the integers Z or rationals Q).

## Comparison Semantics

The comparison methods follow specific rules based on the nature of each cardinal type:

### Equal

| LHS \ RHS    | Known        | Unknown | Infinite |
|--------------|--------------|---------|----------|
| **Known**    | values match | false   | false    |
| **Unknown**  | false        | false   | false    |
| **Infinite** | false        | false   | true     |

- `Known.Equal(Known)`: True if and only if the numeric values are identical.
- `Unknown.Equal(any)`: Always false. Unknown values cannot be compared for equality since their values are hidden.
- `Infinite.Equal(Infinite)`: True. All infinite cardinals are considered equal.

### IsLessThanOrEqual

| LHS \ RHS    | Known     | Unknown | Infinite |
|--------------|-----------|---------|----------|
| **Known**    | numeric ≤ | false   | false    |
| **Unknown**  | false     | false   | false    |
| **Infinite** | false     | false   | true     |

- `Known.IsLessThanOrEqual(Known)`: Standard numeric comparison.
- `Known.IsLessThanOrEqual(Unknown/Infinite)`: False. Known values cannot be compared to unknown or infinite values.
- `Unknown.IsLessThanOrEqual(any)`: Always false. No ordering can be established for unknown values.
- `Infinite.IsLessThanOrEqual(Infinite)`: True. Infinity is considered equal to itself.
- `Infinite.IsLessThanOrEqual(Known/Unknown)`: False. Infinity is not less than any finite or unknown value.

## Type Predicates

- `IsFinite()`: True for Known and Unknown, false for Infinite.
- `IsUnknown()`: True only for Unknown.
- `IsInfinite(c)`: Helper function, true only for Infinite.
- `IsZero()`: True only for Known with value zero.
