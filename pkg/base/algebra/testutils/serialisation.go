package curves_testutils

import (
	"fmt"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	fu "github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
	"github.com/stretchr/testify/require"
)

type NatSerializationInvariants[E algebra.Element] struct{}

type BytesSerializationInvariants[E algebra.BytesSerialization[E]] struct{}

var TestCurves = []curves.Curve{
	bls12381.NewG1(),
	bls12381.NewG2(),
	edwards25519.NewCurve(),
	p256.NewCurve(),
	k256.NewCurve(),
	pallas.NewCurve(),
}

func (nsi *NatSerializationInvariants[E]) Uint64(t *testing.T, object algebra.NatSerialization[E], input E) {
	t.Helper()
	require.NotPanics(t, func() {
		object.Uint64()
	})
	actual := object.Uint64()
	require.IsType(t, uint64(0), actual)
	require.GreaterOrEqual(t, actual, uint64(0))
}

func (nsi *NatSerializationInvariants[E]) SetNatAndNat(t *testing.T, object algebra.NatSerialization[E], boundedCurve curves.Curve) {
	t.Helper()
	output := object.Nat()
	object2 := output.Clone()
	object2.SetNat(object2)
	require.True(t, object2.Eq(output) == 1)

	oneBigEndian := make([]byte, boundedCurve.BaseField().ElementSize())

	if boundedCurve.BaseField().ExtensionDegree().Uint64() == 1 {
		oneBigEndian[len(oneBigEndian)-1] = 0x1
	} else {
		oneBigEndian[len(oneBigEndian)/2-1] = 0x1
	}

	// Check cast from-to Nat
	realFeOne := boundedCurve.BaseField().One()
	feOne := boundedCurve.BaseField().Element().SetNat(saferithUtils.NatOne)
	require.EqualValues(t, realFeOne.Bytes(), feOne.Bytes())
	require.EqualValues(t, oneBigEndian, feOne.Bytes())
	// Check if the internal value is treated as a one
	oneTimesOne := feOne.Mul(feOne)
	require.True(t, feOne.IsOne())
	require.False(t, feOne.IsZero())
	require.True(t, oneTimesOne.IsOne() && !oneTimesOne.IsZero())
}

func (bsi *BytesSerializationInvariants[E]) BytesAndSetBytes(t *testing.T, object algebra.BytesSerialization[E], boundedCurve curves.Curve) {
	t.Helper()

	actual := object.Bytes()
	require.NotZero(t, len(actual))
	excpted, err := object.SetBytes(actual)
	require.NoError(t, err)
	require.Equal(t, excpted, object)

	oneBigEndian := make([]byte, boundedCurve.BaseField().ElementSize())

	if boundedCurve.BaseField().ExtensionDegree().Uint64() == 1 {
		oneBigEndian[len(oneBigEndian)-1] = 0x1
	} else {
		oneBigEndian[len(oneBigEndian)/2-1] = 0x1
	}
	// Check cast from-to bytes
	feOne, err := boundedCurve.BaseField().Element().SetBytes(oneBigEndian)
	require.NoError(t, err)
	require.EqualValues(t, oneBigEndian, feOne.Bytes())
	// Check if the internal value is treated as a one
	oneTimesOne := feOne.Mul(feOne)
	require.True(t, feOne.IsOne() && !feOne.IsZero())
	require.True(t, oneTimesOne.IsOne() && !oneTimesOne.IsZero())
}

func (bsi *BytesSerializationInvariants[E]) BytesAndSetBytesSetBytesWide(t *testing.T, object algebra.BytesSerialization[E], boundedCurve curves.Curve) {
	t.Helper()

	actual := object.Bytes()
	require.NotZero(t, len(actual))
	excpted, err := object.SetBytesWide(actual)
	require.NoError(t, err)
	require.Equal(t, excpted, object)

	oneBigEndian := make([]byte, boundedCurve.BaseField().WideElementSize())
	extensionDegree := boundedCurve.BaseField().ExtensionDegree().Uint64()
	if extensionDegree == 1 {
		oneBigEndian[len(oneBigEndian)-1] = 0x1
	} else {
		oneBigEndian[len(oneBigEndian)/2-1] = 0x1
	}
	// Check cast from-to Nat
	feOne, err := boundedCurve.BaseField().Element().SetBytesWide(oneBigEndian)
	require.NoError(t, err)
	feOneLength := len(feOne.Bytes())

	if extensionDegree == 1 {
		require.EqualValues(t, oneBigEndian[len(oneBigEndian)-feOneLength:], feOne.Bytes())
	} else {
		l := len(oneBigEndian)
		actualA := feOne.Bytes()[:feOneLength/2]
		expectedA := oneBigEndian[l/4 : l/2]
		require.EqualValues(t, expectedA, actualA)
		require.Contains(t, actualA, byte(0x01))

		actualB := feOne.Bytes()[feOneLength/2:]
		expectedB := oneBigEndian[3*l/4:]
		require.EqualValues(t, expectedB, actualB)
		require.NotContains(t, actualB, byte(0x01))
	}

	// Check if the internal value is treated as a one
	oneTimesOne := feOne.Mul(feOne)
	require.True(t, feOne.IsOne() && !feOne.IsZero())
	require.True(t, oneTimesOne.IsOne() && !oneTimesOne.IsZero())
}
func CheckNatSerializationInvariants[E algebra.NatSerialization[E]](t *testing.T, elementGenerator fu.ObjectGenerator[E]) {
	t.Helper()

	nsi := &NatSerializationInvariants[E]{}

	for _, curve := range TestCurves {
		boundedCurve := curve
		t.Run(fmt.Sprintf("SetNatAndNat + %s", boundedCurve.Name()), func(t *testing.T) {
			t.Parallel()
			nsi.SetNatAndNat(t, elementGenerator.Generate(), boundedCurve)
		})
	}
}
func CheckBytesSerializationInvariants[E algebra.BytesSerialization[E]](t *testing.T, elementGenerator fu.ObjectGenerator[E]) {
	t.Helper()

	bsi := &BytesSerializationInvariants[E]{}

	for _, curve := range TestCurves {
		boundedCurve := curve
		t.Run(fmt.Sprintf("BytesAndSetBytes + %s", boundedCurve.Name()), func(t *testing.T) {
			t.Parallel()
			bsi.BytesAndSetBytes(t, elementGenerator.Generate(), boundedCurve)
		})
		t.Run(fmt.Sprintf("BytesAndSetBytesSetBytesWide + %s", boundedCurve.Name()), func(t *testing.T) {
			t.Parallel()
			bsi.BytesAndSetBytesSetBytesWide(t, elementGenerator.Generate(), boundedCurve)
		})
	}
}
