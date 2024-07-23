package schnorr_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"math/big"
	"slices"
	"testing"

	//"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/mina"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/mina"
)

// 8c6e1941732765b2c765ba55257cd4e0ed6872c5ff9a12983247f5719860b437
func Test_Slawek(t *testing.T) {

	skHex := "5a01b3f968dd0e76b1481263f385feb29cf5d5239282063944476acb8fdba6268c30"
	skBytes, err := hex.DecodeString(skHex)
	require.NoError(t, err)
	skRealBytes := skBytes[2:]
	slices.Reverse(skRealBytes[:])
	sk, err := pallas.NewScalarField().Element().SetBytes(skRealBytes)
	require.NoError(t, err)
	pk := pallas.NewCurve().ScalarBaseMult(sk)

	message := new(mina.ROInput).Init()
	message.AddFields(strToField(t, "25195905821302136363746591216053426607730123633199345018456398683787551665804"))
	message.AddFields(strToField(t, "25195905821302136363746591216053426607730123633199345018456398683787551665804"))
	message.AddFields(strToField(t, "12130714382081042136785697490105842824427860728934608176027773023273890851427"))

	bits := []bool{false, false, false, false, false, false, false, false, true, false, false, false, false, true, true, true, true, false, true, false, true, true, true, true, true, false, true, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, true, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, true, false, true, true, false, false, false, true, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, false, false, false, false, false, false, false, true, false, true, false, false, false, false, false, true, false, false, false, false, true, true, false, true, false, true, true, false, false, true, false, true, false, true, false, false, true, true, false, true, false, true, true, false, true, true, false, true, true, true, true, false, true, true, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, true, true, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, true, false, true, false, true, false, false, false, false, true, false, true, false, false, true, false, false, true, true, false, true, true, false, false, false, false, true, false, true, true, false, true, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false}
	for _, b := range bits {
		x := byte(0)
		if b {
			x = byte(1)
		}
		message.Bits.Append(x)
	}

	signer, err := mina.NewSigner(&mina.PrivateKey{S: sk, PublicKey: mina.PublicKey{A: pk}}, mina.TestNet)
	require.NoError(t, err)

	signature, err := signer.Sign(message, crand.Reader)
	require.NoError(t, err)

	println("r", signature.R.AffineX().Nat().Big().Text(10))
	println("s", signature.S.Nat().Big().Text(10))
}

func strToField(t *testing.T, str string) curves.BaseFieldElement {
	t.Helper()

	b, ok := new(big.Int).SetString(str, 10)
	require.True(t, ok)
	n := new(saferith.Nat).SetBig(b, 256)
	s := pallas.NewBaseField().Element().SetNat(n)
	return s
}
