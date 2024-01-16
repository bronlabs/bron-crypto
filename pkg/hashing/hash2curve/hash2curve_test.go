package hashing_test

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	hashing "github.com/copperexchange/krypton-primitives/pkg/hashing/hash2curve"
	"github.com/copperexchange/krypton-primitives/pkg/hashing/hash2curve/testutils"
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
		if curve.Name() != edwards25519.Name {
			t.Run(fmt.Sprintf("hash to curve (%s)", curve.Name()), func(t *testing.T) {
				t.Parallel()
				err := runHash2CurveTests(t, curve, tv)
				require.NoError(t, err)
			})
		}
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
		t.Run(fmt.Sprintf("message: %s", tc.Msg), func(t *testing.T) {
			t.Parallel()

			p, err := ch.Curve().Hash([]byte(tc.Msg))
			require.NoError(t, err)
			if curve.Name() != bls12381.NewG2().Name() {
				expected := readPoint(t, curve, tc.Px, tc.Py)
				require.True(t, p.Equal(expected))
			} else {
				px_expected := dehex(t, tc.Px)
				py_expected := dehex(t, tc.Py)
				pxi_expected := dehex(t, tc.PxI)
				pyi_expected := dehex(t, tc.PyI)

				require.Equal(t, p.AffineX().SubFieldElement(0).Bytes(), (px_expected), 0)
				require.Equal(t, p.AffineX().SubFieldElement(1).Bytes(), (pxi_expected), 0)
				require.Equal(t, p.AffineY().SubFieldElement(0).Bytes(), (py_expected), 0)
				require.Equal(t, p.AffineY().SubFieldElement(1).Bytes(), (pyi_expected), 0)
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
		t.Run(fmt.Sprintf("message: %s", tc.Msg), func(t *testing.T) {
			t.Parallel()

			u, err := ch.HashToFieldElements(2, []byte(tc.Msg), nil)
			require.NoError(t, err)
			if curve.Name() != bls12381.NewG2().Name() {
				u0_expected := readFieldElement(t, tc.U0, curve)
				u1_expected := readFieldElement(t, tc.U1, curve)
				require.True(t, u[0].Equal(u0_expected))
				require.True(t, u[1].Equal(u1_expected))
			} else {
				u0_r_expected := dehex(t, tc.U0)
				u1_r_expected := dehex(t, tc.U1)
				u0_i_expected := dehex(t, tc.U0I)
				u1_i_expected := dehex(t, tc.U1I)

				require.Equal(t, u[0].SubFieldElement(0).Bytes(), (u0_r_expected), 0)
				require.Equal(t, u[0].SubFieldElement(1).Bytes(), (u0_i_expected), 0)
				require.Equal(t, u[1].SubFieldElement(0).Bytes(), (u1_r_expected), 0)
				require.Equal(t, u[1].SubFieldElement(1).Bytes(), (u1_i_expected), 0)
			}
		})
	}
	return nil
}

func readFieldElement(t *testing.T, input string, curve curves.Curve) curves.BaseFieldElement {
	t.Helper()
	feBytes := dehex(t, input)
	fe, err := hashing.MapToFieldElement(curve, feBytes)
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

func dehex(t *testing.T, input string) []byte {
	t.Helper()
	feBytes, err := hex.DecodeString(input)
	require.NoError(t, err)
	return feBytes
}
