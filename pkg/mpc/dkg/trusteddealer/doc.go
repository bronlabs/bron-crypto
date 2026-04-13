// Package trusteddealer provides a centralised dealer that generates shares for
// an arbitrary monotone access structure using Feldman VSS.
//
// WARNING: This package is intended for testing and development only. A trusted
// dealer learns the secret key in plaintext, defeating the purpose of a
// distributed key generation protocol. Production deployments must use a real
// DKG (e.g. [github.com/bronlabs/bron-crypto/pkg/mpc/dkg/canetti] or
// [github.com/bronlabs/bron-crypto/pkg/mpc/dkg/gennaro]).
//
// See README.md for details.
package trusteddealer
