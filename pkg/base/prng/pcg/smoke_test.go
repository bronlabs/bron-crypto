package pcg

import "github.com/bronlabs/bron-crypto/pkg/base/prng"

var _ prng.SeedablePRNG = (*seededReader)(nil)
