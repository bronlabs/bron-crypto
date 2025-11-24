package rfc8937_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/prng"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/csprng/rfc8937"
)

var _ prng.PRNG = (*rfc8937.WrappedReader)(nil)
