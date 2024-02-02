package hash2curve_test

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/hash2curve"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/hash2curve/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

var testCurves = []curves.Curve{
	bls12381.NewG1(),
	bls12381.NewG2(),
	// curve25519.NewCurve(),
	edwards25519.NewCurve(),
	k256.NewCurve(),
	p256.NewCurve(),
}

func Test_VectorsRFC9380(t *testing.T) {
	t.Parallel()
	for _, c := range testCurves {
		curve := c
		tv := testutils.NewHash2CurveTestVector(curve)

		t.Run(fmt.Sprintf("hash to field (%s)", curve.Name()), func(t *testing.T) {
			t.Parallel()
			err := runHash2FieldTests(t, curve, tv)
			require.NoError(t, err)
		})
		t.Run(fmt.Sprintf("hash to curve (%s)", curve.Name()), func(t *testing.T) {
			t.Parallel()
			err := runHash2CurveTests(t, curve, tv)
			require.NoError(t, err)
		})
	}
}

func runHash2CurveTests(t *testing.T, curve curves.Curve, tv *testutils.TestVector) error {
	t.Helper()

	ch, err := testutils.MakeCurveHasher(curve, tv)
	if err != nil {
		return errs.WrapFailed(err, "could not set curve hasher")
	}
	curve = testutils.SetCurveHasher(curve, ch)

	for _, ttc := range tv.TestCases {
		tc := ttc
		t.Run(fmt.Sprintf("message:%s", bitstring.TruncateWithEllipsis(tc.Msg, 20)), func(t *testing.T) {
			t.Parallel()

			p, err := ch.Curve().Hash([]byte(tc.Msg))
			require.NoError(t, err)

			if curve.Name() != bls12381.NewG2().Name() {
				expected := readPoint(t, curve, tc.Px, tc.Py)
				require.EqualValues(t, expected.AffineX().Bytes(), p.AffineX().Bytes())
				require.EqualValues(t, expected.AffineY().Bytes(), p.AffineY().Bytes())
				require.True(t, p.Equal(expected))
			} else {
				pxExpected := hexDecode(t, tc.Px)
				pyExpected := hexDecode(t, tc.Py)
				pxiExpected := hexDecode(t, tc.PxI)
				pyiExpected := hexDecode(t, tc.PyI)

				require.Equal(t, p.AffineX().SubFieldElement(0).Bytes(), pxExpected, 0)
				require.Equal(t, p.AffineX().SubFieldElement(1).Bytes(), pxiExpected, 0)
				require.Equal(t, p.AffineY().SubFieldElement(0).Bytes(), pyExpected, 0)
				require.Equal(t, p.AffineY().SubFieldElement(1).Bytes(), pyiExpected, 0)
			}
		})
	}
	return nil
}

func runHash2FieldTests(t *testing.T, curve curves.Curve, tv *testutils.TestVector) error {
	t.Helper()
	ch, err := testutils.MakeCurveHasher(curve, tv)
	if err != nil {
		return errs.WrapFailed(err, "could not set curve hasher")
	}
	curve = testutils.SetCurveHasher(curve, ch)
	for _, ttc := range tv.TestCases {
		tc := ttc
		t.Run(fmt.Sprintf("message: %s", bitstring.TruncateWithEllipsis(tc.Msg, 20)), func(t *testing.T) {
			t.Parallel()

			u, err := ch.HashToFieldElements(2, []byte(tc.Msg), nil)
			require.NoError(t, err)

			if curve.Name() != bls12381.NewG2().Name() {
				u0Expected := readFieldElement(t, tc.U0, curve)
				u1Expected := readFieldElement(t, tc.U1, curve)
				require.True(t, u[0].Equal(u0Expected))
				require.True(t, u[1].Equal(u1Expected))
			} else {
				u0rExpected := hexDecode(t, tc.U0)
				u1rExpected := hexDecode(t, tc.U1)
				u0iExpected := hexDecode(t, tc.U0I)
				u1iExpected := hexDecode(t, tc.U1I)

				require.Equal(t, u[0].SubFieldElement(0).Bytes(), u0rExpected, 0)
				require.Equal(t, u[0].SubFieldElement(1).Bytes(), u0iExpected, 0)
				require.Equal(t, u[1].SubFieldElement(0).Bytes(), u1rExpected, 0)
				require.Equal(t, u[1].SubFieldElement(1).Bytes(), u1iExpected, 0)
			}
		})
	}
	return nil
}

func readFieldElement(t *testing.T, input string, curve curves.Curve) curves.BaseFieldElement {
	t.Helper()
	feBytes := hexDecode(t, input)
	fe, err := hash2curve.MapToFieldElement(curve, feBytes)
	require.NoError(t, err)
	return fe
}

func readPoint(t *testing.T, curve curves.Curve, x, y string) curves.Point {
	t.Helper()

	exn, err := new(saferith.Nat).SetHex(strings.ToUpper(x))
	require.NoError(t, err)
	eyn, err := new(saferith.Nat).SetHex(strings.ToUpper(y))
	require.NoError(t, err)

	ex := curve.BaseField().Element().SetNat(exn)
	ey := curve.BaseField().Element().SetNat(eyn)

	p, err := curve.NewPoint(ex, ey)
	require.NoError(t, err)
	return p
}

func hexDecode(t *testing.T, input string) []byte {
	t.Helper()
	feBytes, err := hex.DecodeString(input)
	require.NoError(t, err)
	return feBytes
}
