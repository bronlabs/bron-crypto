package rfc8937_test

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/prng/csprng/rfc8937"
)

var _ io.Reader = (*rfc8937.WrappedReader)(nil)
