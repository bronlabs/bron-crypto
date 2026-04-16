# Threshold Access Structure

Implements (t,n) threshold access structures where any subset of at least t shareholders (out of n total) is authorized.

## Usage

```go
ac, err := threshold.NewThresholdAccessStructure(3, shareholders) // 3-of-n
```

## MSP Induction

`InducedMSP` builds an ideal MSP via a Vandermonde matrix, where each shareholder's evaluation point is their ID. The resulting MSP has exactly one row per shareholder.

## Reference

This is the standard threshold structure used by Shamir, Feldman, and Pedersen schemes.
