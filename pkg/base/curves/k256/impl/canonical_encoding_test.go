package impl_test

import (
	"testing"

	k256impl "github.com/bronlabs/bron-crypto/pkg/base/curves/k256/impl"
	curvetestutils "github.com/bronlabs/bron-crypto/pkg/base/curves/testutils"
)

func TestSetBytesRejectsNonCanonicalFieldEncodings(t *testing.T) {
	t.Parallel()

	curvetestutils.AssertCanonicalSetBytes(t, "Fp", k256impl.FpModulus[:], func(data []byte) bool {
		var f k256impl.Fp
		return f.SetBytes(data) == 1
	})
	curvetestutils.AssertCanonicalSetBytes(t, "Fq", k256impl.FqModulus[:], func(data []byte) bool {
		var f k256impl.Fq
		return f.SetBytes(data) == 1
	})
}
