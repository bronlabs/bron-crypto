package curveutils_test

import (
	"bytes"
	crand "crypto/rand"
	"encoding/gob"
	"fmt"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curveutils"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pallas"
)

var TestCurves = []curves.Curve{
	k256.NewCurve(),
	p256.NewCurve(),
	edwards25519.NewCurve(),
	bls12381.NewG1(),
	bls12381.NewG2(),
	// curve25519.NewCurve(),
	pallas.NewCurve(),
}

func init() {
	curveutils.RegisterCurvesForGob()
}

func Test_ScalarMarshalRoundTrip(t *testing.T) {
	t.Parallel()
	for _, c := range TestCurves {
		curve := c
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()
			initial, err := curve.ScalarField().Random(crand.Reader)
			require.NoError(t, err)

			t.Run("json", func(t *testing.T) {
				t.Parallel()

				marshalled, err := initial.MarshalJSON()
				require.NoError(t, err)
				require.NotNil(t, marshalled)

				deserialized, err := curveutils.NewScalarFromJSON(marshalled)
				require.NoError(t, err)
				require.Equal(t, initial.ScalarField().Name(), deserialized.ScalarField().Name())
				require.EqualValues(t, initial.Bytes(), deserialized.Bytes())

				// below is to ensure the G field of the bls scalars are being set correctly.
				require.Equal(t, initial.ScalarField().Curve().Name(), deserialized.ScalarField().Curve().Name())
			})
			t.Run("binary", func(t *testing.T) {
				t.Parallel()

				marshalled, err := curveutils.MarshalScalarToBinary(initial)
				require.NoError(t, err)
				require.NotNil(t, marshalled)

				deserialized, err := curveutils.NewScalarFromBinary(marshalled)
				require.NoError(t, err)
				require.Equal(t, initial.ScalarField().Name(), deserialized.ScalarField().Name())
				require.EqualValues(t, initial.Bytes(), deserialized.Bytes())

				// below is to ensure the G field of the bls scalars are being set correctly.
				require.Equal(t, initial.ScalarField().Curve().Name(), deserialized.ScalarField().Curve().Name())
			})
		})
	}
}

func Test_BaseFieldElementMarshalRoundTrip(t *testing.T) {
	t.Parallel()
	for _, c := range TestCurves {
		curve := c
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()
			initial, err := curve.BaseField().Random(crand.Reader)
			require.NoError(t, err)

			t.Run("json", func(t *testing.T) {
				t.Parallel()

				marshalled, err := initial.MarshalJSON()
				require.NoError(t, err)
				require.NotNil(t, marshalled)

				deserialized, err := curveutils.NewBaseFieldElementFromJSON(marshalled)
				require.NoError(t, err)
				require.Equal(t, initial.BaseField().Name(), deserialized.BaseField().Name())
				require.EqualValues(t, initial.Bytes(), deserialized.Bytes())
			})
			t.Run("binary", func(t *testing.T) {
				t.Parallel()

				marshalled, err := curveutils.MarshalBaseFieldElementToBinary(initial)
				require.NoError(t, err)
				require.NotNil(t, marshalled)

				deserialized, err := curveutils.NewBaseFieldElementFromBinary(marshalled)
				require.NoError(t, err)
				require.Equal(t, initial.BaseField().Name(), deserialized.BaseField().Name())
				require.EqualValues(t, initial.Bytes(), deserialized.Bytes())
			})
		})
	}
}

func Test_PointMarshalRoundTrip(t *testing.T) {
	t.Parallel()
	for _, c := range TestCurves {
		curve := c
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()
			initial, err := curve.Random(crand.Reader)
			require.NoError(t, err)

			t.Run("json", func(t *testing.T) {
				t.Parallel()

				marshalled, err := initial.MarshalJSON()
				require.NoError(t, err)
				require.NotNil(t, marshalled)

				deserialized, err := curveutils.NewPointFromJSON(marshalled)
				require.NoError(t, err)
				require.Equal(t, initial.Curve().Name(), deserialized.Curve().Name())
				require.EqualValues(t, initial.ToAffineUncompressed(), deserialized.ToAffineUncompressed())
			})
			t.Run("binary", func(t *testing.T) {
				t.Parallel()

				marshalled, err := curveutils.MarshalPointToBinary(initial)
				require.NoError(t, err)
				require.NotNil(t, marshalled)

				deserialized, err := curveutils.NewPointFromBinary(marshalled)
				require.NoError(t, err)
				require.Equal(t, initial.Curve().Name(), deserialized.Curve().Name())
				require.EqualValues(t, initial.ToAffineUncompressed(), deserialized.ToAffineUncompressed())
			})
		})
	}
}

type testObject struct {
	P  curves.Point
	Ps []curves.Point
	S  curves.Scalar
	Ss []curves.Scalar
	E  curves.BaseFieldElement
	Es []curves.BaseFieldElement

	X  *saferith.Nat
	Xs []*saferith.Nat

	Value      string
	ArrayValue []string

	Nested *nestedSubTestObject
}

type nestedSubTestObject struct {
	Value string
	P     curves.Point
	S     curves.Scalar
	X     *saferith.Nat
}

func Test_GobRoundTrip(t *testing.T) {
	t.Parallel()
	for i, curve1 := range TestCurves {
		for j, curve2 := range TestCurves {
			if i != j {
				c1 := curve1
				c2 := curve2
				numberOfFieldsOfTestObject := 11
				for nilIndex := 0; nilIndex < numberOfFieldsOfTestObject; nilIndex++ {
					ni := nilIndex
					tn := fmt.Sprintf("testing gob round trip for %s and secondary %s with nil index %d", c1.Name(), c2.Name(), ni)
					t.Run(tn, func(t *testing.T) {
						t.Parallel()

						to := &testObject{}

						p, err := c1.Random(crand.Reader)
						require.NoError(t, err)
						if ni != 0 {
							to.P = p
						}

						ps0, err := c1.Random(crand.Reader)
						require.NoError(t, err)
						ps1, err := c2.Random(crand.Reader)
						require.NoError(t, err)
						if ni != 1 {
							to.Ps = []curves.Point{ps0, ps1}
						}

						s, err := c1.ScalarField().Random(crand.Reader)
						require.NoError(t, err)
						if ni != 2 {
							to.S = s
						}

						ss0, err := c1.ScalarField().Random(crand.Reader)
						require.NoError(t, err)
						ss1, err := c2.ScalarField().Random(crand.Reader)
						require.NoError(t, err)
						if ni != 3 {
							to.Ss = []curves.Scalar{ss0, ss1}
						}

						e, err := c1.BaseField().Random(crand.Reader)
						require.NoError(t, err)
						if ni != 4 {
							to.E = e
						}

						es0, err := c1.BaseField().Random(crand.Reader)
						require.NoError(t, err)
						es1, err := c2.BaseField().Random(crand.Reader)
						require.NoError(t, err)
						if ni != 5 {
							to.Es = []curves.BaseFieldElement{es0, es1}
						}

						x := p.AffineX().Nat()
						if ni != 6 {
							to.X = x
						}

						xs := []*saferith.Nat{ps0.AffineX().Nat(), ps1.AffineX().Nat()}
						if ni != 7 {
							to.Xs = xs
						}

						value := tn
						if ni != 8 {
							to.Value = value
						}

						arrayValue := []string{c1.Name(), c2.Name()}
						if ni != 9 {
							to.ArrayValue = arrayValue
						}

						nested := &nestedSubTestObject{
							Value: tn,
							P:     p,
							S:     s,
							X:     x,
						}
						if ni != 10 {
							to.Nested = nested
						}

						var buf bytes.Buffer

						enc := gob.NewEncoder(&buf)
						err = enc.Encode(to)
						require.NoError(t, err)

						dec := gob.NewDecoder(&buf)
						var decoded testObject

						err = dec.Decode(&decoded)
						require.NoError(t, err)

						if ni != 0 {
							require.NotNil(t, decoded.P)
							require.EqualValues(t, p.ToAffineCompressed(), decoded.P.ToAffineCompressed())
						} else {
							require.Nil(t, decoded.P)
						}
						if ni != 1 {
							require.NotNil(t, decoded.Ps)
							require.Len(t, decoded.Ps, 2)
							require.EqualValues(t, ps0.ToAffineCompressed(), decoded.Ps[0].ToAffineCompressed())
							require.EqualValues(t, ps1.ToAffineCompressed(), decoded.Ps[1].ToAffineCompressed())
						} else {
							require.Nil(t, decoded.Ps)
						}

						if ni != 2 {
							require.NotNil(t, decoded.S)
							require.EqualValues(t, s.Bytes(), decoded.S.Bytes())
						} else {
							require.Nil(t, decoded.S)
						}

						if ni != 3 {
							require.NotNil(t, decoded.Ss)
							require.Len(t, decoded.Ss, 2)
							require.EqualValues(t, ss0.Bytes(), decoded.Ss[0].Bytes())
							require.EqualValues(t, ss1.Bytes(), decoded.Ss[1].Bytes())
						} else {
							require.Nil(t, decoded.Ss)
						}

						if ni != 4 {
							require.NotNil(t, decoded.E)
							require.EqualValues(t, e.Bytes(), decoded.E.Bytes())
						} else {
							require.Nil(t, decoded.E)
						}

						if ni != 5 {
							require.NotNil(t, decoded.Es)
							require.Len(t, decoded.Es, 2)
							require.EqualValues(t, es0.Bytes(), decoded.Es[0].Bytes())
							require.EqualValues(t, es1.Bytes(), decoded.Es[1].Bytes())
						} else {
							require.Nil(t, decoded.Es)
						}

						if ni != 6 {
							require.NotNil(t, decoded.X)
							require.EqualValues(t, x.Bytes(), decoded.X.Bytes())
						} else {
							require.Nil(t, decoded.X)
						}

						if ni != 7 {
							require.NotNil(t, decoded.Xs)
							require.Len(t, decoded.Xs, 2)
							require.EqualValues(t, xs[0].Bytes(), decoded.Xs[0].Bytes())
							require.EqualValues(t, xs[1].Bytes(), decoded.Xs[1].Bytes())
						} else {
							require.Nil(t, decoded.Xs)
						}

						if ni != 8 {
							require.NotEmpty(t, decoded.Value)
							require.Equal(t, tn, decoded.Value)
						} else {
							require.Empty(t, decoded.Value)
						}

						if ni != 9 {
							require.NotNil(t, decoded.ArrayValue)
							require.EqualValues(t, to.ArrayValue, decoded.ArrayValue)
						} else {
							require.Nil(t, decoded.ArrayValue)
						}

						if ni != 10 {
							require.NotNil(t, decoded.Nested)
							require.Equal(t, to.Nested.Value, decoded.Nested.Value)
							require.EqualValues(t, to.Nested.P.ToAffineCompressed(), decoded.Nested.P.ToAffineCompressed())
							require.EqualValues(t, to.Nested.S.Bytes(), decoded.Nested.S.Bytes())
							require.EqualValues(t, x.Bytes(), decoded.Nested.X.Bytes())
						} else {
							require.Nil(t, decoded.Nested)
						}
					})

				}
			}
		}
	}

}
