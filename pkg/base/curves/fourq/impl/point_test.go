package impl_test

import (
	"encoding/hex"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/fourq/impl"
)

func Test_PointDouble(t *testing.T) {
	p := new(impl.ExtendedPoint).Generator()
	for range 1000 {
		p.Double(p)
	}
	p.ToAffine(p)

	// taken from https://github.com/microsoft/FourQlib/blob/master/FourQ_ARM/tests/ecc_tests.c
	xExpected, err := hex.DecodeString("4DA5B9E83AA7A1B2A7B3F6E2043E8E682C3FD8822C82270FC9099C54855859D6")
	require.NoError(t, err)
	yExpected, err := hex.DecodeString("0FFDB0D761421F501FEE5617A7E954CD2001EB3A576883963EE089F0EB49AA14")
	require.NoError(t, err)
	slices.Reverse(xExpected)
	slices.Reverse(yExpected)

	require.Equal(t, xExpected, p.GetX().ToBytes())
	require.Equal(t, yExpected, p.GetY().ToBytes())
}

func Test_PointAdd(t *testing.T) {
	p := new(impl.ExtendedPoint).Generator()
	for range 1000 {
		p.Add(p, p)
	}
	p.ToAffine(p)

	// taken from https://github.com/microsoft/FourQlib/blob/master/FourQ_ARM/tests/ecc_tests.c
	xExpected, err := hex.DecodeString("4DA5B9E83AA7A1B2A7B3F6E2043E8E682C3FD8822C82270FC9099C54855859D6")
	require.NoError(t, err)
	yExpected, err := hex.DecodeString("0FFDB0D761421F501FEE5617A7E954CD2001EB3A576883963EE089F0EB49AA14")
	require.NoError(t, err)
	slices.Reverse(xExpected)
	slices.Reverse(yExpected)

	require.Equal(t, xExpected, p.GetX().ToBytes())
	require.Equal(t, yExpected, p.GetY().ToBytes())
}

func Test_PointAddUnique(t *testing.T) {
	q := new(impl.ExtendedPoint).Generator()
	p := new(impl.ExtendedPoint).Double(q)
	for range 1000 {
		p.Add(p, q)
	}
	p.ToAffine(p)

	// taken from https://github.com/microsoft/FourQlib/blob/master/FourQ_ARM/tests/ecc_tests.c
	xExpected, err := hex.DecodeString("5327AF7D84238CD0AA270F644A65D4733E243958590C4D906480B1EF0A151DB0")
	require.NoError(t, err)
	yExpected, err := hex.DecodeString("293EB1E26DD23B4E4E752648AC2EF0AB3EF69A49CB7E02375E06003D73C43EB1")
	require.NoError(t, err)
	slices.Reverse(xExpected)
	slices.Reverse(yExpected)

	require.Equal(t, xExpected, p.GetX().ToBytes())
	require.Equal(t, yExpected, p.GetY().ToBytes())
}

func Test_PointMul(t *testing.T) {
	q := new(impl.ExtendedPoint).Generator()
	p := new(impl.ExtendedPoint).Identity()
	sUint64 := uint64(1002)

	for range sUint64 {
		p.Add(p, q)
	}
	p.ToAffine(p)

	sFq := new(impl.Fq).SetUint64(sUint64)
	sLimbs := sFq.Limbs()
	p2 := new(impl.ExtendedPoint).Mul(q, &sLimbs)
	p2.ToAffine(p2)

	//taken from https://github.com/microsoft/FourQlib/blob/master/FourQ_ARM/tests/ecc_tests.c
	xExpected, err := hex.DecodeString("5327AF7D84238CD0AA270F644A65D4733E243958590C4D906480B1EF0A151DB0")
	require.NoError(t, err)
	yExpected, err := hex.DecodeString("293EB1E26DD23B4E4E752648AC2EF0AB3EF69A49CB7E02375E06003D73C43EB1")
	require.NoError(t, err)
	slices.Reverse(xExpected)
	slices.Reverse(yExpected)

	require.Equal(t, p2.GetX().ToBytes(), xExpected) //nolint:testifylint // false positive
	require.Equal(t, p2.GetY().ToBytes(), yExpected) //nolint:testifylint // false positive
	require.Equal(t, p.GetX().ToBytes(), p2.GetX().ToBytes())
	require.Equal(t, p.GetY().ToBytes(), p2.GetY().ToBytes())
}

func Test_PointSerialisation(t *testing.T) {
	q := new(impl.ExtendedPoint).Generator()
	p := new(impl.ExtendedPoint).Identity()
	sUint64 := uint64(1002)

	for range sUint64 {
		p.Add(p, q)
		compressed := p.ToCompressed()
		uncompressed, err := new(impl.ExtendedPoint).FromCompressed(compressed)
		require.NoError(t, err)
		pAffine := new(impl.ExtendedPoint).ToAffine(p)
		uncompressed.ToAffine(uncompressed)

		require.Equal(t, uint64(1), pAffine.GetX().Equal(uncompressed.GetX()))
		require.Equal(t, uint64(1), pAffine.GetY().Equal(uncompressed.GetY()))
	}
}
