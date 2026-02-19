// Package additive implements additive secret sharing over arbitrary groups.
//
// In additive secret sharing, a secret s is split into n shares s_1, ..., s_n
// such that s = s_1 + s_2 + ... + s_n (using the group operation). This is an
// n-of-n scheme: all shares are required to reconstruct the secret.
//
// Additive sharing is information-theoretically secure: any proper subset of
// shares reveals no information about the secret. It is commonly used as a
// building block in MPC protocols and as the target representation when
// converting Shamir shares via Lagrange coefficients.
package additive
