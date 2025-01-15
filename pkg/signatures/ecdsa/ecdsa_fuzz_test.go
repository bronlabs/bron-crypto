package ecdsa_test

import (
	nativeEcdsa "crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"hash"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/p256"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/hashing"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/ecdsa"
)

var allCurves = []curves.Curve{k256.NewCurve(), p256.NewCurve()}
var allHashes = []func() hash.Hash{sha256.New, sha3.New256}

func Fuzz_Test(f *testing.F) {
	f.Add(uint(0), uint(0), []byte{0x00})
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, message []byte) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		hashFunc := allHashes[int(hashIndex)%len(allHashes)]
		nativeCurve := elliptic.P256()

		messageHash, err := hashing.Hash(hashFunc, message)
		require.NoError(t, err)

		nativePrivateKey, err := nativeEcdsa.GenerateKey(nativeCurve, crand.Reader)
		require.NoError(t, err)
		nativePublicKey := &nativePrivateKey.PublicKey

		publicKey, err := curve.NewPoint(
			curve.BaseField().Element().SetNat(new(saferith.Nat).SetBig(nativePublicKey.X, curve.BaseField().Order().BitLen())),
			curve.BaseField().Element().SetNat(new(saferith.Nat).SetBig(nativePublicKey.Y, curve.BaseField().Order().BitLen())),
		)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip(err.Error())
		}
		require.NoError(t, err)

		nativeR, nativeS, err := nativeEcdsa.Sign(crand.Reader, nativePrivateKey, messageHash)
		require.NoError(t, err)

		r := curve.ScalarField().Element().SetNat(new(saferith.Nat).SetBig(nativeR, curve.Order().BitLen()))
		s := curve.ScalarField().Element().SetNat(new(saferith.Nat).SetBig(nativeS, curve.Order().BitLen()))
		verified := false
		for v := 0; v < 4; v++ {
			if verified == false {
				err = ecdsa.Verify(&ecdsa.Signature{V: &v, R: r, S: s}, hashFunc, publicKey, message)
				if err == nil {
					verified = true
				}
			}
		}
		require.True(t, verified)
	})
}
