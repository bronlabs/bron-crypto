package impl_test

import (
	"testing"

	pastaimpl "github.com/bronlabs/bron-crypto/pkg/base/curves/pasta/impl"
	curvetestutils "github.com/bronlabs/bron-crypto/pkg/base/curves/testutils"
)

func TestSetBytesRejectsNonCanonicalFieldEncodings(t *testing.T) {
	t.Parallel()

	curvetestutils.AssertCanonicalSetBytes(t, "Fp", pastaimpl.FpModulus[:], func(data []byte) bool {
		var f pastaimpl.Fp
		return f.SetBytes(data) == 1
	})
	curvetestutils.AssertCanonicalSetBytes(t, "Fq", pastaimpl.FqModulus[:], func(data []byte) bool {
		var f pastaimpl.Fq
		return f.SetBytes(data) == 1
	})
}
