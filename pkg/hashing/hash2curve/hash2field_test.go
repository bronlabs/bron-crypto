package hash2curve_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
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
		u0Bytes := u[0].Bytes()
		u1Bytes := u[1].Bytes()
		expu0Bytes, _ := hex.DecodeString(tc.U0)
		expu1Bytes, _ := hex.DecodeString(tc.U1)
		expu0BytesR := bitstring.ReverseBytes(expu0Bytes)
		expu1BytesR := bitstring.ReverseBytes(expu1Bytes)
		if !bytes.Equal(u0Bytes, expu0Bytes) || !bytes.Equal(u0Bytes, expu0BytesR) {
			return errs.NewVerificationFailed("hash to field element failed: u0 mismatch")
		}
		if !bytes.Equal(u1Bytes, expu1Bytes) || !bytes.Equal(u1Bytes, expu1BytesR) {
			return errs.NewVerificationFailed("hash to field element failed: u1 mismatch")
		}
	}
	return nil
}
