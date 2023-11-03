package hash2curve_test

import (
	"encoding/hex"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing/hash2curve/testutils"
)

var testCurves = []curves.Curve{
	// bls12381.NewG1(),
	// bls12381.NewG2(),
	// curve25519.New(),
	// edwards25519.New(),
	k256.New(),
	// p256.New(),
}

func Test_HashToField_VectorsRFC9380(t *testing.T) {
	for _, curve := range testCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			tv := testutils.NewHash2CurveTestVector(curve)
			err := RunTestVector(curve, tv)
			require.NoError(t, err)
		})
	}
}

func RunTestVector(curve curves.Curve, tv *testutils.TestVector) error {
	ch, err := testutils.SetCurveHasher(curve, tv)
	if err != nil {
		return errs.WrapFailed(err, "could not set curve hasher")
	}
	for _, tc := range tv.TestCases {
		// expMsgUs, _ := ch.ExpandMessage([]byte(tc.Msg), []byte(tv.Dst), 96)
		// expMsgUs2, _ := ch.ExpandMessage([]byte(tc.Msg), ch.Dst(), 96)
		// expMsgTrue := hash2curve.ExpandMsgXmd(hash2curve.EllipticCurveHasherSha256(), []byte(tc.Msg), []byte(tv.Dst), 96)
		// if !bytes.Equal(expMsgUs, expMsgTrue) || !bytes.Equal(expMsgUs2, expMsgTrue) {
		// 	return errs.NewVerificationFailed("expand message failed: mismatch")
		// }

		u, err := ch.HashToFieldElement([]byte(tc.Msg), 2)
		if err != nil {
			return errs.WrapFailed(err, "hash to field element failed")
		}
		expu0Bytes, _ := hex.DecodeString(tc.U0)
		expu1Bytes, _ := hex.DecodeString(tc.U1)
		u0Nat := new(saferith.Nat).SetBytes(expu0Bytes)
		u1Nat := new(saferith.Nat).SetBytes(expu1Bytes)

		if u[0].Nat().Eq(u0Nat) != 1 {
			return errs.NewVerificationFailed("hash to field element failed: u0 mismatch")
		}
		if u[1].Nat().Eq(u1Nat) != 1 {
			return errs.NewVerificationFailed("hash to field element failed: u1 mismatch")
		}
	}
	return nil
}
