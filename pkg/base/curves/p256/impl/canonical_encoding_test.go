package impl_test

import (
	"testing"

	p256impl "github.com/bronlabs/bron-crypto/pkg/base/curves/p256/impl"
	curvetestutils "github.com/bronlabs/bron-crypto/pkg/base/curves/testutils"
)

func TestSetBytesRejectsNonCanonicalFieldEncodings(t *testing.T) {
	t.Parallel()

	curvetestutils.AssertCanonicalSetBytes(t, "Fp", p256impl.FpModulus[:], func(data []byte) bool {
		var f p256impl.Fp
		return f.SetBytes(data) == 1
	})
	curvetestutils.AssertCanonicalSetBytes(t, "Fq", p256impl.FqModulus[:], func(data []byte) bool {
		var f p256impl.Fq
		return f.SetBytes(data) == 1
	})
}
