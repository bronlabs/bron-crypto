# Additive Secret Sharing

Implements n-of-n additive secret sharing over arbitrary groups.

## Security

- Information-theoretic: any proper subset of shares reveals nothing
- Requires all shares: missing even one share prevents reconstruction

## Usage

```go
ac, _ := sharing.NewUnanimityAccessStructure(shareholders)
scheme, _ := additive.NewScheme(group, ac)

// Deal shares
output, _ := scheme.Deal(secret, prng)
shares := output.Shares()

// Reconstruct (all shares required)
recovered, _ := scheme.Reconstruct(share1, share2, ..., shareN)
```

## How It Works

The secret s is split into n shares such that s = s_1 + s_2 + ... + s_n (using the group operation). All but one share are sampled randomly; the final share is computed to satisfy the constraint.

## Common Use Cases

- Building block for MPC protocols
- Target representation when converting Shamir shares via Lagrange coefficients
- Simple secret splitting when all parties must cooperate
