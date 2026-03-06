package pasta_test

import (
	"math/big"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

func Test_PallasBaseElementCBORRoundTrip(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	e, err := pasta.NewPallasBaseField().Random(prng)
	require.NoError(t, err)
	serialised, err := cbor.Marshal(e)
	require.NoError(t, err)
	deserialized := new(pasta.PallasBaseFieldElement)
	err = cbor.Unmarshal(serialised, &deserialized)
	require.NoError(t, err)
	require.True(t, deserialized.Equal(e))
}

func Test_PallasScalarCBORRoundTrip(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	e, err := pasta.NewPallasScalarField().Random(prng)
	require.NoError(t, err)
	serialised, err := cbor.Marshal(e)
	require.NoError(t, err)
	deserialized := new(pasta.PallasScalar)
	err = cbor.Unmarshal(serialised, &deserialized)
	require.NoError(t, err)
	require.True(t, deserialized.Equal(e))
}

func Test_PallasPointCBORRoundTrip(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	e, err := pasta.NewPallasCurve().Random(prng)
	require.NoError(t, err)
	serialised, err := cbor.Marshal(e)
	require.NoError(t, err)
	deserialized := new(pasta.PallasPoint)
	err = cbor.Unmarshal(serialised, &deserialized)
	require.NoError(t, err)
	require.True(t, deserialized.Equal(e))
}

func Test_VestaBaseElementCBORRoundTrip(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	e, err := pasta.NewVestaBaseField().Random(prng)
	require.NoError(t, err)
	serialised, err := cbor.Marshal(e)
	require.NoError(t, err)
	deserialized := new(pasta.VestaBaseFieldElement)
	err = cbor.Unmarshal(serialised, &deserialized)
	require.NoError(t, err)
	require.True(t, deserialized.Equal(e))
}

func Test_VestaScalarCBORRoundTrip(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	e, err := pasta.NewVestaScalarField().Random(prng)
	require.NoError(t, err)
	serialised, err := cbor.Marshal(e)
	require.NoError(t, err)
	deserialized := new(pasta.VestaScalar)
	err = cbor.Unmarshal(serialised, &deserialized)
	require.NoError(t, err)
	require.True(t, deserialized.Equal(e))
}

func Test_VestaPointCBORRoundTrip(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	e, err := pasta.NewVestaCurve().Random(prng)
	require.NoError(t, err)
	serialised, err := cbor.Marshal(e)
	require.NoError(t, err)
	deserialized := new(pasta.VestaPoint)
	err = cbor.Unmarshal(serialised, &deserialized)
	require.NoError(t, err)
	require.True(t, deserialized.Equal(e))
}

func Test_PallasEllipticPointOnCurve(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	ellipticCurve := pasta.NewPallasCurve().ToElliptic()
	p, err := pasta.NewPallasCurve().Random(prng)
	require.NoError(t, err)
	x, err := p.AffineX()
	require.NoError(t, err)
	y, err := p.AffineY()
	require.NoError(t, err)
	xInt := new(big.Int).SetBytes(x.BytesBE())
	yInt := new(big.Int).SetBytes(y.BytesBE())
	ok := ellipticCurve.IsOnCurve(xInt, yInt)
	require.True(t, ok)
}

func Test_VestaEllipticPointOnCurve(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	ellipticCurve := pasta.NewVestaCurve().ToElliptic()
	p, err := pasta.NewVestaCurve().Random(prng)
	require.NoError(t, err)
	x, err := p.AffineX()
	require.NoError(t, err)
	y, err := p.AffineY()
	require.NoError(t, err)
	xInt := new(big.Int).SetBytes(x.BytesBE())
	yInt := new(big.Int).SetBytes(y.BytesBE())
	ok := ellipticCurve.IsOnCurve(xInt, yInt)
	require.True(t, ok)
}
