# Shamir Secret Sharing

Implements Shamir's (t,n) threshold secret sharing scheme.

## Security

- Information-theoretic: t-1 or fewer shares reveal nothing about the secret
- Perfect secrecy: no computational assumptions required

## Usage

```go
scheme, _ := shamir.NewScheme(field, threshold, shareholders)

// Deal shares
output, _ := scheme.Deal(secret, prng)
shares := output.Shares()

// Reconstruct
recovered, _ := scheme.Reconstruct(share1, share2, ..., shareT)
```

## How It Works

The secret s is encoded as the constant term of a random polynomial f(x) of degree t-1. Each share is a point (i, f(i)) on the polynomial. Any t shares can reconstruct s via Lagrange interpolation.

## Reference

Shamir, A. "How to Share a Secret." Communications of the ACM, 1979.
