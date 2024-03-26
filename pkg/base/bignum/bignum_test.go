package bignum_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"github.com/copperexchange/krypton-primitives/pkg/base/bignum"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_ExpCrt(t *testing.T) {
	prng := crand.Reader
	pBig, err := crand.Prime(prng, 256)
	require.NoError(t, err)
	p := new(saferith.Nat).SetBig(pBig, 512)

	qBig, err := crand.Prime(prng, 256)
	require.NoError(t, err)
	q := new(saferith.Nat).SetBig(qBig, 512)
	if b, _, _ := p.Cmp(q); b == 1 {
		p, q = q, p
	}

	secretKey, err := paillier.NewSecretKey(p, q)
	require.NoError(t, err)

	baseBig, err := crand.Int(prng, secretKey.N.Big())
	require.NoError(t, err)
	base := new(saferith.Nat).SetBig(baseBig, secretKey.N.AnnouncedLen())

	expBig, err := crand.Int(prng, secretKey.N.Big())
	require.NoError(t, err)
	exp := new(saferith.Nat).SetBig(expBig, secretKey.N.AnnouncedLen())

	resultSlow := new(saferith.Nat).Exp(base, exp, secretKey.GetNModulus())
	resultCrt := bignum.ExpCrt(secretKey.GetCrtNParams(), base, exp, secretKey.GetNModulus())
	resultFast := bignum.FastExpCrt(secretKey.GetCrtNParams(), base, exp, secretKey.GetNModulus())

	println(hex.EncodeToString(resultSlow.Bytes()))
	println(hex.EncodeToString(resultCrt.Bytes()))
	println(hex.EncodeToString(resultFast.Bytes()))
}

//func Test_ParallelBaseExp(t *testing.T) {
//	pNat, err := new(saferith.Nat).SetHex(strings.ToUpper("f8a6a87aba7440451a6dd0abb1ff33aa16f932e8b90eed81ef0cd988304dfe1f97e290ba8a4f7244e1626120a9fd05c37c4b79f20e9d5086bcf6eba8e67b1c22639ea274cd71738ba7195557149e804c60a01da0b0a124e2163092c4476aa2886e37e3e7207306ddc6e3008774e6fad140ee7929fd8cc0f5c63c451dd285759ea9a4fc306bdc06572287ba903fbe86e31c50babd8e2871498f2e28e457715e1a3674af98302bea9a558f8f0694cffcf073e45d94226a79c6510c13decb68b141bf931a911648b7b08f502a0b7ec7461075e9dff70aba6a39d5549eee49e6185a339a07f605872af7b2428a6aca64454bbeae61f288de31a6533507c96d97881f"))
//	require.NoError(t, err)
//
//	qNat, err := new(saferith.Nat).SetHex(strings.ToUpper("a09325f212364da0456f049956bbf651cd7b82502bfabd733639f6b75ec878bbb8740187a7031754121ad750085e9a029651112b58b5750b72ee16d6e1b04ca79429ca77ef37ce387555c54af8b6c23f1a9854db84a69ae65ff84541a90454c8f4983c88d121b50024519fe32f7ebdfa5b1551511051e129d3e70f1bee0aecfae3475924e1eb7ad40e2c33a27f126efea78a2fcd8a7bc6845f27224f06279f35d6c8d82d81b088871e8c5b564a94d5e78212ff6c11146094cad6e69491211a9f344489a0c045b1b9395a30c5100faf9de8b86074f1d5c4fffe36addc60e65bfcb7c5889f677e1e1be447f37e8c5f122d3f2fd107600663234ce9eff57928625b"))
//	require.NoError(t, err)
//
//	pqNat := new(saferith.Nat).Mul(pNat, qNat, 4096)
//	pqMod := saferith.ModulusFromNat(pqNat)
//
//	base, err := crand.Int(crand.Reader, pqNat.Big())
//	require.NoError(t, err)
//	baseNat := new(saferith.Nat).SetBytes(base.Bytes())
//
//	exponents := make([]*saferith.Nat, 128)
//	for i := range exponents {
//		eInt, err := crand.Int(crand.Reader, pqNat.Big())
//		require.NoError(t, err)
//		exponents[i] = new(saferith.Nat).SetBytes(eInt.Bytes())
//	}
//
//	r := FastFixedBaseMultiExp(baseNat, exponents, pqNat)
//
//	for i := range exponents {
//		check := new(saferith.Nat).Exp(baseNat, exponents[i], pqMod)
//		require.True(t, check.Eq(r[i]) == 1)
//	}
//}
//
//func Test_ParallelExponentExp(t *testing.T) {
//	pNat, err := new(saferith.Nat).SetHex(strings.ToUpper("f8a6a87aba7440451a6dd0abb1ff33aa16f932e8b90eed81ef0cd988304dfe1f97e290ba8a4f7244e1626120a9fd05c37c4b79f20e9d5086bcf6eba8e67b1c22639ea274cd71738ba7195557149e804c60a01da0b0a124e2163092c4476aa2886e37e3e7207306ddc6e3008774e6fad140ee7929fd8cc0f5c63c451dd285759ea9a4fc306bdc06572287ba903fbe86e31c50babd8e2871498f2e28e457715e1a3674af98302bea9a558f8f0694cffcf073e45d94226a79c6510c13decb68b141bf931a911648b7b08f502a0b7ec7461075e9dff70aba6a39d5549eee49e6185a339a07f605872af7b2428a6aca64454bbeae61f288de31a6533507c96d97881f"))
//	require.NoError(t, err)
//
//	qNat, err := new(saferith.Nat).SetHex(strings.ToUpper("a09325f212364da0456f049956bbf651cd7b82502bfabd733639f6b75ec878bbb8740187a7031754121ad750085e9a029651112b58b5750b72ee16d6e1b04ca79429ca77ef37ce387555c54af8b6c23f1a9854db84a69ae65ff84541a90454c8f4983c88d121b50024519fe32f7ebdfa5b1551511051e129d3e70f1bee0aecfae3475924e1eb7ad40e2c33a27f126efea78a2fcd8a7bc6845f27224f06279f35d6c8d82d81b088871e8c5b564a94d5e78212ff6c11146094cad6e69491211a9f344489a0c045b1b9395a30c5100faf9de8b86074f1d5c4fffe36addc60e65bfcb7c5889f677e1e1be447f37e8c5f122d3f2fd107600663234ce9eff57928625b"))
//	require.NoError(t, err)
//
//	pqNat := new(saferith.Nat).Mul(pNat, qNat, 4096)
//	pqMod := saferith.ModulusFromNat(pqNat)
//
//	exponent, err := crand.Int(crand.Reader, pqNat.Big())
//	require.NoError(t, err)
//	exponentNat := new(saferith.Nat).SetBytes(exponent.Bytes())
//
//	bases := make([]*saferith.Nat, 128)
//	for i := range bases {
//		bInt, err := crand.Int(crand.Reader, pqNat.Big())
//		require.NoError(t, err)
//		bases[i] = new(saferith.Nat).SetBytes(bInt.Bytes())
//	}
//
//	r := FastFixedExponentMultiExp(bases, exponentNat, pqNat)
//
//	for i := range bases {
//		check := new(saferith.Nat).Exp(bases[i], exponentNat, pqMod)
//		require.True(t, check.Eq(r[i]) == 1)
//	}
//}
//
//func Benchmark_Compare(b *testing.B) {
//	pNat, err := new(saferith.Nat).SetHex(strings.ToUpper("f8a6a87aba7440451a6dd0abb1ff33aa16f932e8b90eed81ef0cd988304dfe1f97e290ba8a4f7244e1626120a9fd05c37c4b79f20e9d5086bcf6eba8e67b1c22639ea274cd71738ba7195557149e804c60a01da0b0a124e2163092c4476aa2886e37e3e7207306ddc6e3008774e6fad140ee7929fd8cc0f5c63c451dd285759ea9a4fc306bdc06572287ba903fbe86e31c50babd8e2871498f2e28e457715e1a3674af98302bea9a558f8f0694cffcf073e45d94226a79c6510c13decb68b141bf931a911648b7b08f502a0b7ec7461075e9dff70aba6a39d5549eee49e6185a339a07f605872af7b2428a6aca64454bbeae61f288de31a6533507c96d97881f"))
//	require.NoError(b, err)
//
//	qNat, err := new(saferith.Nat).SetHex(strings.ToUpper("a09325f212364da0456f049956bbf651cd7b82502bfabd733639f6b75ec878bbb8740187a7031754121ad750085e9a029651112b58b5750b72ee16d6e1b04ca79429ca77ef37ce387555c54af8b6c23f1a9854db84a69ae65ff84541a90454c8f4983c88d121b50024519fe32f7ebdfa5b1551511051e129d3e70f1bee0aecfae3475924e1eb7ad40e2c33a27f126efea78a2fcd8a7bc6845f27224f06279f35d6c8d82d81b088871e8c5b564a94d5e78212ff6c11146094cad6e69491211a9f344489a0c045b1b9395a30c5100faf9de8b86074f1d5c4fffe36addc60e65bfcb7c5889f677e1e1be447f37e8c5f122d3f2fd107600663234ce9eff57928625b"))
//	require.NoError(b, err)
//
//	pqNat := new(saferith.Nat).Mul(pNat, qNat, 4096)
//	pqMod := saferith.ModulusFromNat(pqNat)
//
//	aInt, err := crand.Int(crand.Reader, pqNat.Big())
//	require.NoError(b, err)
//	bInt, err := crand.Int(crand.Reader, pqNat.Big())
//	require.NoError(b, err)
//
//	aNat := new(saferith.Nat).SetBytes(aInt.Bytes())
//	bNat := new(saferith.Nat).SetBytes(bInt.Bytes())
//
//	rNat := new(saferith.Nat).Exp(aNat, bNat, pqMod)
//	r2Nat := FastExp(aNat, bNat, pqMod.Nat())
//
//	println(hex.EncodeToString(rNat.Bytes()))
//	println(hex.EncodeToString(r2Nat.Bytes()))
//	require.True(b, rNat.Eq(r2Nat) == 1)
//
//	b.ResetTimer()
//	b.Run("saferith", func(b *testing.B) {
//		for i := 0; i < b.N; i++ {
//			cInt, _ := crand.Int(crand.Reader, pqNat.Big())
//			dInt, _ := crand.Int(crand.Reader, pqNat.Big())
//
//			cNat := new(saferith.Nat).SetBytes(cInt.Bytes())
//			dNat := new(saferith.Nat).SetBytes(dInt.Bytes())
//			_ = new(saferith.Nat).Exp(cNat, dNat, pqMod)
//		}
//	})
//
//	b.ResetTimer()
//	b.Run("BoringBigNum", func(b *testing.B) {
//		for i := 0; i < b.N; i++ {
//			cInt, _ := crand.Int(crand.Reader, pqNat.Big())
//			dInt, _ := crand.Int(crand.Reader, pqNat.Big())
//
//			cNat := new(saferith.Nat).SetBytes(cInt.Bytes())
//			dNat := new(saferith.Nat).SetBytes(dInt.Bytes())
//			_ = FastExp(cNat, dNat, pqMod.Nat())
//		}
//	})
//}
