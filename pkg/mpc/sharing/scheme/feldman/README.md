# Feldman Verifiable Secret Sharing

Extends Shamir's scheme with public verification of shares.

## Security

- Computational hiding: secret hidden under discrete log assumption
- Public verifiability: shareholders can verify their shares without interaction

## Usage

```go
ac, _ := sharing.NewThresholdAccessStructure(threshold, shareholders)
scheme, _ := feldman.NewScheme(basePoint, ac)

// Deal shares with verification vector
output, _ := scheme.Deal(secret, prng)
shares := output.Shares()
verificationVector := output.VerificationMaterial()

// Verify a share
err := scheme.Verify(share, verificationVector)

// Reconstruct
recovered, _ := scheme.Reconstruct(share1, share2, ..., shareT)
```

## How It Works

The dealer publishes commitments C_j = g^{a_j} for each coefficient a_j of the dealing polynomial. Shareholders verify their share s_i by checking g^{s_i} = product of C_j^{i^j}.

## Reference

Feldman, P. "A Practical Scheme for Non-interactive Verifiable Secret Sharing." FOCS, 1987.
