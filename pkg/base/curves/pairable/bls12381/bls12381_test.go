package bls12381_test

import (
	"encoding"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

func Test_G1BaseFieldElementCBORRoundTrip(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

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
	prng := pcg.NewRandomised()

	e, err := bls12381.NewScalarField().Random(prng)
	require.NoError(t, err)
	serialised, err := cbor.Marshal(e)
	require.NoError(t, err)
	deserialized := new(bls12381.Scalar)
	err = cbor.Unmarshal(serialised, &deserialized)
	require.NoError(t, err)
	require.True(t, deserialized.Equal(e))
}

func Test_PPEEqualSameEngine(t *testing.T) {
	t.Parallel()
	ppe1 := bls12381.NewOptimalAtePPE()
	ppe2 := bls12381.NewOptimalAtePPE()
	require.True(t, ppe1.Equal(ppe2),
		"two instances of the same pairing engine must be Equal")
}

func Test_G1PointCBORRoundTrip(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

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
	prng := pcg.NewRandomised()

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
	prng := pcg.NewRandomised()

	e, err := bls12381.NewG2().Random(prng)
	require.NoError(t, err)
	serialised, err := cbor.Marshal(e)
	require.NoError(t, err)
	deserialized := new(bls12381.PointG2)
	err = cbor.Unmarshal(serialised, &deserialized)
	require.NoError(t, err)
	require.True(t, deserialized.Equal(e))
}

func Test_G2BaseFieldElementTraitBehaviour(t *testing.T) {
	t.Parallel()

	f := bls12381.NewG2BaseField()
	zero := f.Zero()
	one := f.One()

	require.True(t, zero.IsZero())
	require.False(t, zero.IsOne())
	require.True(t, one.IsOne())
	require.False(t, one.IsZero())
	require.True(t, one.Double().Equal(one.Add(one)))

	x, err := f.Hash([]byte("clone-me"))
	require.NoError(t, err)
	clone := x.Clone()
	require.True(t, clone.Equal(x))
	require.False(t, clone.IsZero())
}

func Test_GtBinaryRoundTrip(t *testing.T) {
	t.Parallel()

	gt := bls12381.NewGt()
	one := gt.One()

	require.Equal(t, len(one.Bytes()), gt.ElementSize())

	decoded, err := gt.FromBytes(one.Bytes())
	require.NoError(t, err)
	require.True(t, decoded.Equal(one))

	data, err := one.MarshalBinary()
	require.NoError(t, err)
	require.Len(t, data, gt.ElementSize())

	var unmarshaled bls12381.GtElement
	err = unmarshaled.UnmarshalBinary(data)
	require.NoError(t, err)
	require.True(t, unmarshaled.Equal(one))
}

func Test_G2BaseFieldOrder(t *testing.T) {
	t.Parallel()

	fpOrder := bls12381.NewG1BaseField().Order()
	expected := fpOrder.Mul(fpOrder)
	require.Equal(t, expected.String(), bls12381.NewG2BaseField().Order().String())
}

var (
	_ encoding.BinaryMarshaler   = (*bls12381.GtElement)(nil)
	_ encoding.BinaryUnmarshaler = (*bls12381.GtElement)(nil)
)
