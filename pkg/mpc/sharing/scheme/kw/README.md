# Karchmer-Wigderson MSP-Based Secret Sharing

Implements secret sharing for arbitrary linear access structures via monotone span programmes (MSPs).

## Overview

The KW scheme generalises Shamir's threshold scheme to any monotone access structure that admits an MSP. Given a linear access structure, the scheme induces an MSP matrix **M** and uses it for both dealing and reconstruction.

**Dealing:** sample a random column vector **r** with r[0] = secret, compute **lambda** = **M** * **r**, and distribute the rows of **lambda** to shareholders according to the MSP labelling.

**Reconstruction:** given a qualified set of shares, solve for coefficients **c** such that **c**^T * **M_I** = **target**, then recover the secret as the dot product **c** . **lambda_I**.

## Supported Access Structures

Any `accessstructures.Monotone` implementation, including:

- **Threshold** — (t, n) quorums
- **Unanimity** — all-or-nothing (n-of-n)
- **CNF** — conjunctive normal form (specified by maximal unqualified sets)
- **Hierarchical** — hierarchical conjunctive threshold (via Birkhoff-Vandermonde MSP induction)

## Homomorphic Properties

Shares are linearly homomorphic over the base field:

- `share(a).Add(share(b))` reconstructs to `a + b`
- `share(a).ScalarMul(k)` reconstructs to `k * a`

## Usage

```go
field := k256.NewScalarField()
ac, _ := threshold.NewThresholdAccessStructure(2, shareholders)
scheme, _ := kw.NewScheme(field, ac)

// Deal
out, _ := scheme.Deal(kw.NewSecret(field.FromUint64(42)), prng)

// Reconstruct from any qualified subset
secret, _ := scheme.Reconstruct(share1, share2)
```

## Reference

- [M. Karchmer and A. Wigderson, "On Span Programs."](https://www.math.ias.edu/~avi/PUBLICATIONS/MYPAPERS/KW93/proc.pdf)
