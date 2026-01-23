package pcg //nolint:testpackage // to test unexported identifiers

import "github.com/bronlabs/bron-crypto/pkg/base/prng"

var _ prng.SeedablePRNG = (*Pcg)(nil)
