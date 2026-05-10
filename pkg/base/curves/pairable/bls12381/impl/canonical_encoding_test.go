package impl_test

import (
	"testing"

	bls12381impl "github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381/impl"
	curvetestutils "github.com/bronlabs/bron-crypto/pkg/base/curves/testutils"
)

func TestSetBytesRejectsNonCanonicalFieldEncodings(t *testing.T) {
	t.Parallel()

	curvetestutils.AssertCanonicalSetBytes(t, "Fp", bls12381impl.FpModulus[:], func(data []byte) bool {
		var f bls12381impl.Fp
		return f.SetBytes(data) == 1
	})
	curvetestutils.AssertCanonicalSetBytes(t, "Fq", bls12381impl.FqModulus[:], func(data []byte) bool {
		var f bls12381impl.Fq
		return f.SetBytes(data) == 1
	})
}
