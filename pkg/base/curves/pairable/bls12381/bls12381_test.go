package bls12381_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
)

func Test_G1BaseFieldElementCBORRoundTrip(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	e, err := bls12381.NewG1BaseField().Random(prng)
	require.NoError(t, err)
	serialised, err := cbor.Marshal(e)
	require.NoError(t, err)
	deserialized := new(bls12381.BaseFieldElementG1)
	err = cbor.Unmarshal(serialised, &deserialized)
	require.NoError(t, err)
	require.True(t, deserialized.Equal(e))
}

func Test_ScalarCBORRoundTrip(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	e, err := bls12381.NewScalarField().Random(prng)
	require.NoError(t, err)
	serialised, err := cbor.Marshal(e)
	require.NoError(t, err)
	deserialized := new(bls12381.Scalar)
	err = cbor.Unmarshal(serialised, &deserialized)
	require.NoError(t, err)
	require.True(t, deserialized.Equal(e))
}

func Test_G1PointCBORRoundTrip(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	e, err := bls12381.NewG1().Random(prng)
	require.NoError(t, err)
	serialised, err := cbor.Marshal(e)
	require.NoError(t, err)
	deserialized := new(bls12381.PointG1)
	err = cbor.Unmarshal(serialised, &deserialized)
	require.NoError(t, err)
	require.True(t, deserialized.Equal(e))
}

func Test_G2BaseFieldElementCBORRoundTrip(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	e, err := bls12381.NewG2BaseField().Random(prng)
	require.NoError(t, err)
	serialised, err := cbor.Marshal(e)
	require.NoError(t, err)
	deserialized := new(bls12381.BaseFieldElementG2)
	err = cbor.Unmarshal(serialised, &deserialized)
	require.NoError(t, err)
	require.True(t, deserialized.Equal(e))
}

func Test_G2PointCBORRoundTrip(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	e, err := bls12381.NewG2().Random(prng)
	require.NoError(t, err)
	serialised, err := cbor.Marshal(e)
	require.NoError(t, err)
	deserialized := new(bls12381.PointG2)
	err = cbor.Unmarshal(serialised, &deserialized)
	require.NoError(t, err)
	require.True(t, deserialized.Equal(e))
}
