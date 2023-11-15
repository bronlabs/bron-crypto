package hashing_test

import (
	"encoding/hex"
	"testing"

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
	// bls12381.NewG2(),
	// curve25519.New(),
	edwards25519.New(),
	k256.New(),
	p256.New(),
}

func Test_HashToField_VectorsRFC9380(t *testing.T) {
	for _, curve := range testCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			tv := testutils.NewHash2CurveTestVector(curve)
			err := RunTestVector(t, curve, tv)
			require.NoError(t, err)
		})
	}
}

func RunTestVector(t *testing.T, curve curves.Curve, tv *testutils.TestVector) error {
	t.Helper()
	ch, err := testutils.SetCurveHasher(curve, tv)
	if err != nil {
		return errs.WrapFailed(err, "could not set curve hasher")
	}
	for _, tc := range tv.TestCases {
		u, err := ch.HashToFieldElements(2, []byte(tc.Msg), nil)
		if err != nil {
			return errs.WrapFailed(err, "hash to field element failed")
		}
		u0_expected := ReadTestFieldElement(tc.U0, curve)
		u1_expected := ReadTestFieldElement(tc.U1, curve)
		require.Zero(t, u[0].Cmp(u0_expected))
		require.Zero(t, u[1].Cmp(u1_expected))
	}
	return nil
}

func ReadTestFieldElement(input string, curve curves.Curve) curves.FieldElement {
	feBytes, err := hex.DecodeString(input)
	if err != nil {
		panic(err)
	}
	fe, err := hashing.MapToFieldElement(curve, feBytes)
	if err != nil {
		panic(err)
	}
	return fe
}
