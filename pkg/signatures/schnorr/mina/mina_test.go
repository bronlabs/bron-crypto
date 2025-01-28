package mina_test

import (
	crand "crypto/rand"
	"math/big"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves/pasta"
	"github.com/bronlabs/krypton-primitives/pkg/hashing/poseidon"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/schnorr"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/schnorr/mina"
)

func Test_MinaSignaturePrefix(t *testing.T) {
	t.Parallel()

	// Refer to: https://github.com/MinaProtocol/mina/blob/develop/docs/specs/signatures/description.md
	// for expected values

	t.Run("Mainnet", func(t *testing.T) {
		t.Parallel()
		testPrefix(t, mina.SignaturePrefix(mina.MainNet), "25220214331362653986409717908235786107802222826119905443072293294098933388948")
	})

	t.Run("Testnet", func(t *testing.T) {
		t.Parallel()
		testPrefix(t, mina.SignaturePrefix(mina.TestNet), "28132119227444686413214523693400847740858213284875453355294308721084881982354")
	})
}

func Test_MinaSignMessage(t *testing.T) {
	t.Parallel()
	curve := pasta.NewPallasCurve()
	networkId := mina.MainNet
	variant := mina.NewMinaVariant(networkId)

	// All values obtained from O(1) labs mina-signer.

	sk := strToScalar(t, "20987758534052335737424525003440476959853367412571910582080213595473581573783")
	pk := curve.ScalarBaseMult(sk)
	require.Equal(t, "3929268416187492872735679104545903402832124076488796084449036732480426604286", pk.AffineX().Nat().Big().Text(10))
	require.Equal(t, "17177737068384989387274570176766583852489456632411397305336352510811099980774", pk.AffineY().Nat().Big().Text(10))

	kPrime := strToScalar(t, "13540458141279025394791744498503443551383645444468870651612319497045334654360")
	r := curve.ScalarBaseMult(kPrime)
	require.Equal(t, "10569506600743131621294488096494870133191640342063019788448197901714521682111", r.AffineX().Nat().Big().Text(10))
	require.Equal(t, "28387199546673507202866414450281545215199183201766863666714284315614039951407", r.AffineY().Nat().Big().Text(10))

	message := new(mina.ROInput).Init()
	message.AddString("hello")

	e, err := variant.ComputeChallenge(nil, r, pk, message)
	require.NoError(t, err)
	require.Equal(t, "9310433820357165272756969594426807319217514677183163841930245378477675655019", e.Nat().Big().Text(10))

	s := variant.ComputeResponse(r, pk, kPrime, sk, e)
	require.Equal(t, "1147363613546017217873377756251595721734598843121909033414348376891634407165", s.Nat().Big().Text(10))

	publicKey := &mina.PublicKey{A: pk}
	signature := schnorr.NewSignature(variant, e, r, s)

	err = mina.Verify(publicKey, signature, message, networkId)
	require.NoError(t, err)
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	prng := crand.Reader
	networkId := mina.MainNet

	sk, pk, err := mina.KeyGen(prng)
	require.NoError(t, err)

	signer, err := mina.NewSigner(sk, networkId)
	require.NoError(t, err)

	message := new(mina.ROInput).Init()
	message.AddString("Hello World!")

	signature, err := signer.Sign(message, prng)
	require.NoError(t, err)

	err = mina.Verify(pk, signature, message, networkId)
	require.NoError(t, err)
}

func strToScalar(t *testing.T, str string) *pasta.PallasScalar {
	t.Helper()

	b, ok := new(big.Int).SetString(str, 10)
	require.True(t, ok)
	n := new(saferith.Nat).SetBig(b, 256)
	s := pasta.NewPallasScalarField().Element().SetNat(n)
	return s.(*pasta.PallasScalar)
}

func testPrefix(t *testing.T, prefix mina.Prefix, expectedString string) {
	t.Helper()

	fe, err := prefix.ToBaseFieldElement()
	require.NoError(t, err)

	p := poseidon.NewLegacy()
	p.Hash(fe)
	result := p.Digest()

	expectedInt, ok := new(big.Int).SetString(expectedString, 10)
	require.True(t, ok)
	expectedNat := new(saferith.Nat).SetBig(expectedInt, 256)
	expected := pasta.NewPallasBaseField().Element().SetNat(expectedNat)
	require.True(t, result.Equal(expected))
}
