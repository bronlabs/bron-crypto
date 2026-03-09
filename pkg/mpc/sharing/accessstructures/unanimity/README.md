# Unanimity Access Structure

Implements n-of-n access structures where all shareholders must participate to reconstruct the secret.

## Usage

```go
ac, err := unanimity.NewUnanimityAccessStructure(shareholders)
```

## MSP Induction

`InducedByUnanimity` converts the unanimity structure to CNF form (n singleton clauses, one per shareholder) and builds the MSP from that representation.

## Reference

This is the access structure underlying additive secret sharing.
