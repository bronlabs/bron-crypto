package k256_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func Test_BaseFieldElementCBORRoundTrip(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	e, err := k256.NewBaseField().Random(prng)
	require.NoError(t, err)
	serialized, err := cbor.Marshal(e)
	require.NoError(t, err)
	deserialized := new(k256.BaseFieldElement)
	err = cbor.Unmarshal(serialized, &deserialized)
	require.NoError(t, err)
	require.True(t, deserialized.Equal(e))
}

func Test_ScalarGobRoundTrip(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	e, err := k256.NewScalarField().Random(prng)
	require.NoError(t, err)
	serialized, err := cbor.Marshal(e)
	require.NoError(t, err)
	deserialized := new(k256.Scalar)
	err = cbor.Unmarshal(serialized, &deserialized)
	require.NoError(t, err)
	require.True(t, deserialized.Equal(e))
}

func Test_PointGobRoundTrip(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	e, err := k256.NewCurve().Random(prng)
	require.NoError(t, err)
	serialized, err := cbor.Marshal(e)
	require.NoError(t, err)
	deserialized := new(k256.Point)
	err = cbor.Unmarshal(serialized, &deserialized)
	require.NoError(t, err)
	require.True(t, deserialized.Equal(e))
}
