package fuzz

import (
	nativeEddsa "crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/core/hashing"
	"github.com/copperexchange/knox-primitives/pkg/signatures/eddsa"
)

var allCurves = []curves.Curve{edwards25519.New()}
var allHashes = []func() hash.Hash{sha256.New, sha3.New256}

func Fuzz_Test(f *testing.F) {
	f.Add(uint(0), uint(0), []byte{0x00})
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, msg []byte) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		h := allHashes[int(hashIndex)%len(allHashes)]

		messageHash, err := hashing.Hash(h, msg)
		require.NoError(t, err)
		p, privateKey, err := nativeEddsa.GenerateKey(crand.Reader)
		require.NoError(t, err)
		publicKey, err := curve.Point().FromAffineCompressed(p)
		require.NoError(t, err)
		signed := nativeEddsa.Sign(privateKey, messageHash)
		R, err := curve.Point().FromAffineCompressed(signed[:32])
		require.NoError(t, err)
		Z, err := curve.Scalar().SetBytes(signed[32:])
		require.NoError(t, err)
		signature := &eddsa.Signature{
			R: R,
			Z: Z,
		}
		err = eddsa.Verify(curve, h, signature, publicKey, messageHash)
		require.NoError(t, err)
	})
}
