package fuzz

import (
	nativeEddsa "crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha512"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/eddsa"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
)

var allCurves = []curves.Curve{edwards25519.NewCurve()}
var allHashes = []func() hash.Hash{sha512.New}

func Fuzz_Test(f *testing.F) {
	f.Add(uint(0), uint(0), []byte{0x00})
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, msg []byte) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		h := allHashes[int(hashIndex)%len(allHashes)]
		suite, err := ttu.MakeSignatureProtocol(curve, h)
		require.NoError(t, err)

		messageHash, err := hashing.Hash(h, msg)
		require.NoError(t, err)
		p, privateKey, err := nativeEddsa.GenerateKey(crand.Reader)
		require.NoError(t, err)
		publicKey, err := curve.Point().FromAffineCompressed(p)
		require.NoError(t, err)
		signed := nativeEddsa.Sign(privateKey, messageHash)
		R, err := curve.Point().FromAffineCompressed(signed[:32])
		require.NoError(t, err)
		s, err := curve.Scalar().SetBytes(bitstring.ReverseBytes(signed[32:]))
		require.NoError(t, err)
		signature := schnorr.NewSignature(schnorr.NewEdDsaCompatibleVariant(), nil, R, s)
		err = eddsa.Verify(suite, &eddsa.PublicKey{A: publicKey}, messageHash, signature)
		require.NoError(t, err)
	})
}
