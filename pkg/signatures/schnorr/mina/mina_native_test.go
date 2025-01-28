package mina_test

import (
	crand "crypto/rand"
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/pasta"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/schnorr/mina"
)

func Test_SignAgainstMinaSigner(t *testing.T) {
	t.Parallel()
	network := mina.MainNet

	// gen keys and create signer
	sk, err := pasta.NewPallasScalarField().Random(crand.Reader)
	require.NoError(t, err)
	signer, err := mina.NewSigner(&mina.PrivateKey{S: sk}, network)
	require.NoError(t, err)

	// sample random fields
	var fields [4]curves.BaseFieldElement
	for i := range fields {
		randomFe, err := pasta.NewPallasBaseField().Random(crand.Reader)
		require.NoError(t, err)
		fields[i] = randomFe

	}
	input := new(mina.ROInput).Init()
	input.AddFields(fields[:]...)

	// sample random bits
	var bits [300]bool
	for i := range bits {
		bits[i] = (rand.Uint64() % 2) != 0
	}
	input.AddBits(bits[:]...)

	// sign input
	signature, err := signer.Sign(input, crand.Reader)
	require.NoError(t, err)

	// verify
	pk := pasta.NewPallasCurve().ScalarBaseMult(sk)
	err = mina.Verify(&mina.PublicKey{A: pk}, signature, input, network)
	require.NoError(t, err)

	// spit out data, so it can be verified with mina signer
	println("r", signature.R.AffineX().Nat().Big().Text(10))
	println("s", signature.S.Nat().Big().Text(10))
	println("fields:")
	for _, f := range fields {
		println(f.Nat().Big().Text(10))
	}
	bitsStr := "["
	for _, b := range bits {
		bStr := "false,"
		if b {
			bStr = "true,"
		}
		bitsStr = bitsStr + bStr
	}
	bitsStr = bitsStr + "]"
	println("bits", bitsStr)
	println("x", pk.AffineX().Nat().Big().Text(10))
	println("isOdd", pk.AffineY().IsOdd())
}
