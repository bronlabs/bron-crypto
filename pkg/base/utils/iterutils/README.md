# Iterutils

Functional utilities for working with Go 1.23+ iterators (`iter.Seq` and `iter.Seq2`), enabling lazy evaluation and efficient data processing.

## Features

- **Transformations** - Map, filter, and transform sequences
- **Composition** - Concatenate, flatten, and zip sequences
- **Predicates** - Check conditions across sequences (any, all, contains, equal)
- **Reductions** - Reduce sequences to single values with error handling
- **Truncation** - Limit sequence length

Supports both single-value (`iter.Seq`) and key-value pair (`iter.Seq2`) iterators with generic types.
