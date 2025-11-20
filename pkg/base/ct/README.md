# Constant-Time Helpers

Package `ct` provides constant-time operations for cryptographic implementations, helping to prevent timing-based side-channel attacks.

## Overview

This package offers constant-time primitives for:

- **Integer operations**: comparisons, selection, min/max, and arithmetic operations on signed and unsigned integers
- **Byte slice operations**: comparison, XOR, AND, OR, and NOT operations
- **Conditional operations**: constant-time selection, assignment, swapping, and negation
- **Choice type**: a constant-time boolean for use in cryptographic code

All operations are designed to execute in time independent of their inputs, making them suitable for cryptographic applications where timing leaks could expose sensitive data.

## Key Types

- `Choice`: A constant-time boolean type (0 or 1)
- Interfaces: `Comparable`, `Equatable`, `ConditionallySelectable`, `ConditionallyAssignable`, `ConditionallyNegatable`

## Usage

Use this package when implementing cryptographic algorithms that require resistance to timing attacks. All comparison and conditional operations are designed to avoid data-dependent branching and maintain constant execution time.