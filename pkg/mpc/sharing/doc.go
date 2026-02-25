// Package sharing defines interfaces and types for secret sharing schemes.
//
// Secret sharing allows a dealer to distribute a secret among n shareholders
// such that only authorized subsets can reconstruct it. This package provides
// the common abstractions used by concrete implementations (Shamir, Feldman,
// Pedersen, additive).
//
// The main interface hierarchy is:
//   - SSS: Basic secret sharing scheme
//   - VSSS: Verifiable secret sharing (adds share verification)
//   - LSSS: Linear secret sharing (shares form a vector space)
//   - PolynomialLSSS: Polynomial-based LSSS (e.g., Shamir)
package sharing
