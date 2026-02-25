# Pedersen Verifiable Secret Sharing

Extends Feldman VSS with information-theoretic hiding.

## Security

- Information-theoretic hiding: secret hidden even against unbounded adversaries
- Public verifiability: shareholders can verify shares using Pedersen commitments

## Usage

```go
ac, _ := sharing.NewThresholdAccessStructure(threshold, shareholders)
scheme, _ := pedersen.NewScheme(pedersenKey, ac)

// Deal shares with verification vector
output, _ := scheme.Deal(secret, prng)
shares := output.Shares()          // each share has (secret, blinding) components
verificationVector := output.VerificationVector()

// Verify a share
err := scheme.Verify(share, verificationVector)

// Reconstruct
recovered, _ := scheme.Reconstruct(share1, share2, ..., shareT)
```

## How It Works

Uses two random polynomials: f(x) for the secret and r(x) for blinding. Each share consists of (f(i), r(i)). The verification vector contains Pedersen commitments C_j = g^{a_j} * h^{b_j}. Verification checks g^{s_i} * h^{t_i} against the evaluation of the verification vector.

## Reference

Pedersen, T. "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing." CRYPTO, 1991.
