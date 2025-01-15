package eddsa_test

import (
	nativeEddsa "crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha512"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/bitstring"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/bronlabs/krypton-primitives/pkg/hashing"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/eddsa"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/schnorr"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/schnorr/vanilla"
)

var allCurves = []curves.Curve{edwards25519.NewCurve()}
var allHashes = []func() hash.Hash{sha512.New}

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
		s, err := curve.ScalarField().Element().SetBytes(bitstring.ReverseBytes(signed[32:]))
		require.NoError(t, err)
		signature := schnorr.NewSignature(vanilla.NewEdDsaCompatibleVariant(), nil, R, s)
		err = eddsa.Verify(&eddsa.PublicKey{A: publicKey}, messageHash, signature)
		require.NoError(t, err)
	})
}
