package impl_test

import (
	"testing"

	edwards25519impl "github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519/impl"
	curvetestutils "github.com/bronlabs/bron-crypto/pkg/base/curves/testutils"
)

func TestSetBytesRejectsNonCanonicalFieldEncodings(t *testing.T) {
	t.Parallel()

	curvetestutils.AssertCanonicalSetBytes(t, "Fp", edwards25519impl.FpModulus[:], func(data []byte) bool {
		var f edwards25519impl.Fp
		return f.SetBytes(data) == 1
	})
	curvetestutils.AssertCanonicalSetBytes(t, "Fq", edwards25519impl.FqModulus[:], func(data []byte) bool {
		var f edwards25519impl.Fq
		return f.SetBytes(data) == 1
	})
}
