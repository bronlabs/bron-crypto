package curves_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	edwards25519Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519/impl"
	k256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/k256/impl"
	p256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/p256/impl"
	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381/impl"
	pastaImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/pasta/impl"
)

type fieldElement interface {
	SetBytes(data []byte) ct.Bool
	Bytes() []byte
}

func Test_FieldSetBytesRejectsNonCanonical(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		newElement func() fieldElement
		modulus    []byte
		size       int
	}{
		{"p256 Fp", func() fieldElement { return new(p256Impl.Fp) }, p256Impl.FpModulus[:], p256Impl.FpBytes},
		{"p256 Fq", func() fieldElement { return new(p256Impl.Fq) }, p256Impl.FqModulus[:], p256Impl.FqBytes},
		{"k256 Fp", func() fieldElement { return new(k256Impl.Fp) }, k256Impl.FpModulus[:], k256Impl.FpBytes},
		{"k256 Fq", func() fieldElement { return new(k256Impl.Fq) }, k256Impl.FqModulus[:], k256Impl.FqBytes},
		{"bls12381 Fp", func() fieldElement { return new(bls12381Impl.Fp) }, bls12381Impl.FpModulus[:], bls12381Impl.FpBytes},
		{"bls12381 Fq", func() fieldElement { return new(bls12381Impl.Fq) }, bls12381Impl.FqModulus[:], bls12381Impl.FqBytes},
		{"pasta Fp", func() fieldElement { return new(pastaImpl.Fp) }, pastaImpl.FpModulus[:], pastaImpl.FpBytes},
		{"pasta Fq", func() fieldElement { return new(pastaImpl.Fq) }, pastaImpl.FqModulus[:], pastaImpl.FqBytes},
		{"edwards25519 Fq", func() fieldElement { return new(edwards25519Impl.Fq) }, edwards25519Impl.FqModulus[:], edwards25519Impl.FqBytes},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			modulus := make([]byte, tc.size)
			copy(modulus, tc.modulus)
			maxCanonical := slices.Clone(modulus)
			maxCanonical[0]--

			zero := make([]byte, tc.size)
			e := tc.newElement()
			require.Equal(t, ct.True, e.SetBytes(zero))
			require.Equal(t, zero, e.Bytes())

			e = tc.newElement()
			require.Equal(t, ct.True, e.SetBytes(maxCanonical))
			require.Equal(t, maxCanonical, e.Bytes())

			require.Equal(t, ct.False, tc.newElement().SetBytes(modulus))
			require.Equal(t, ct.False, tc.newElement().SetBytes(bytes.Repeat([]byte{0xff}, tc.size)))
		})
	}
}
