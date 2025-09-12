package p256_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func Test_BaseFieldElementCBORRoundTrip(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	e, err := p256.NewBaseField().Random(prng)
	require.NoError(t, err)
	serialized, err := cbor.Marshal(e)
	require.NoError(t, err)
	deserialized := new(p256.BaseFieldElement)
	err = cbor.Unmarshal(serialized, &deserialized)
	require.NoError(t, err)
	require.True(t, deserialized.Equal(e))
}

func Test_ScalarCBORRoundTrip(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	e, err := p256.NewScalarField().Random(prng)
	require.NoError(t, err)
	serialized, err := cbor.Marshal(e)
	require.NoError(t, err)
	deserialized := new(p256.Scalar)
	err = cbor.Unmarshal(serialized, &deserialized)
	require.NoError(t, err)
	require.True(t, deserialized.Equal(e))
}

func Test_PointCBORRoundTrip(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	e, err := p256.NewCurve().Random(prng)
	require.NoError(t, err)
	serialized, err := cbor.Marshal(e)
	require.NoError(t, err)
	deserialized := new(p256.Point)
	err = cbor.Unmarshal(serialized, &deserialized)
	require.NoError(t, err)
	require.True(t, deserialized.Equal(e))
}
