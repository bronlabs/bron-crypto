package p256_test

import (
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	p256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/p256/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

func Test_FromCompressedRejectsNonCanonicalX(t *testing.T) {
	t.Parallel()

	x := slices.Clone(p256Impl.FpModulus[:])
	slices.Reverse(x)
	for _, sign := range []byte{0x02, 0x03} {
		_, err := p256.NewCurve().FromCompressed(append([]byte{sign}, x...))
		require.Error(t, err)
	}
}

func Test_BaseFieldElementCBORRoundTrip(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	e, err := p256.NewBaseField().Random(prng)
	require.NoError(t, err)
	serialised, err := cbor.Marshal(e)
	require.NoError(t, err)
	deserialized := new(p256.BaseFieldElement)
	err = cbor.Unmarshal(serialised, &deserialized)
	require.NoError(t, err)
	require.True(t, deserialized.Equal(e))
}

func Test_ScalarCBORRoundTrip(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	e, err := p256.NewScalarField().Random(prng)
	require.NoError(t, err)
	serialised, err := cbor.Marshal(e)
	require.NoError(t, err)
	deserialized := new(p256.Scalar)
	err = cbor.Unmarshal(serialised, &deserialized)
	require.NoError(t, err)
	require.True(t, deserialized.Equal(e))
}

func Test_PointCBORRoundTrip(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	e, err := p256.NewCurve().Random(prng)
	require.NoError(t, err)
	serialised, err := cbor.Marshal(e)
	require.NoError(t, err)
	deserialized := new(p256.Point)
	err = cbor.Unmarshal(serialised, &deserialized)
	require.NoError(t, err)
	require.True(t, deserialized.Equal(e))
}
