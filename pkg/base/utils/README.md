# Utils

Common utility functions and helpers for working with Go primitives and data structures.

## Packages

- **sliceutils** - Utilities for working with slices (map, filter, reduce, shuffle, etc.)
- **maputils** - Utilities for working with maps (transformations, merging, submap checking)
- **iterutils** - Utilities for working with Go iterators (map, filter, zip, concat, etc.)
- **algebrautils** - Utilities for working with algebraic structures (scalar multiplication, folding, etc.)
- **mathutils** - Mathematical utilities and number operations
- **nocopy** - Types to prevent copying of structs

## Core Functions

- `BoolTo[T]` - Convert boolean to any integer type
- `IsNil[T]` - Check if a value is nil (handles pointers and interfaces)
- `LeadingZeroBytes` - Count leading zero bytes in a byte slice
- `ImplementsX[X, T]` - Check if a value implements an interface
- `Binomial` - Compute binomial coefficients
