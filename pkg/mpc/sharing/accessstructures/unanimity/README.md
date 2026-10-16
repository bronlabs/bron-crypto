# Unanimity Access Structure

Implements n-of-n access structures where all shareholders must participate to reconstruct the secret.

## Usage

```go
ac, err := unanimity.NewUnanimityAccessStructure(shareholders)
```

## MSP Induction

`InducedMSP` constructs the ideal monotone span programme for additive sharing.

## Reference

<!-- paper: docs/papers/2025-518_20250319_142628.pdf [Example 1.1] -->
<!-- paper: docs/papers/2025-518_20250319_142628.pdf [Section 4.2, Figure 4.3] -->
This is the access structure underlying additive secret sharing.
