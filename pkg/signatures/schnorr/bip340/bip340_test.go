package bip340_test

import (
	"bytes"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/bip340"
)

func Test_BIP340TestVectors(t *testing.T) {
	t.Parallel()

	type testVectorData struct {
		privateKey string
		publicKey  string
		aux        string
		message    string
		signature  string
		valid      bool

		_ ds.Incomparable
	}
	vectorData := []testVectorData{
		{ // 0
			privateKey: "0000000000000000000000000000000000000000000000000000000000000003",
			publicKey:  "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
			aux:        "0000000000000000000000000000000000000000000000000000000000000000",
			message:    "0000000000000000000000000000000000000000000000000000000000000000",
			signature:  "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
			valid:      true,
		},
		{ // 1
			privateKey: "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
			publicKey:  "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			aux:        "0000000000000000000000000000000000000000000000000000000000000001",
			message:    "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			signature:  "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
			valid:      true,
		},
		{ // 2
			privateKey: "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
			publicKey:  "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
			aux:        "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
			message:    "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
			signature:  "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
			valid:      true,
		},
		{ // 3
			privateKey: "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
			publicKey:  "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
			aux:        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			message:    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			signature:  "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
			valid:      true,
		},
		{ // 4
			privateKey: "",
			publicKey:  "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
			aux:        "",
			message:    "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
			signature:  "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
			valid:      true,
		},
		{ // 5
			privateKey: "",
			publicKey:  "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
			aux:        "",
			message:    "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			signature:  "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
			valid:      false, // public key not on the curve
		},
		{ // 6
			privateKey: "",
			publicKey:  "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			aux:        "",
			message:    "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			signature:  "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
			valid:      false, // has_even_y(R) is false
		},
		{ // 7
			privateKey: "",
			publicKey:  "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			aux:        "",
			message:    "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			signature:  "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD",
			valid:      false, // negated message
		},
		{ // 8
			privateKey: "",
			publicKey:  "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			aux:        "",
			message:    "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			signature:  "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6",
			valid:      false, // negated s value
		},
		{ // 9
			privateKey: "",
			publicKey:  "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			aux:        "",
			message:    "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			signature:  "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051",
			valid:      false, // sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 0
		},
		{ // 10
			privateKey: "",
			publicKey:  "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			aux:        "",
			message:    "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			signature:  "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197",
			valid:      false, // sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 1
		},
		{ // 11
			privateKey: "",
			publicKey:  "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			aux:        "",
			message:    "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			signature:  "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
			valid:      false, // sig[0:32] is not an X coordinate on the curve
		},
		{ // 12
			privateKey: "",
			publicKey:  "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			aux:        "",
			message:    "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			signature:  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
			valid:      false, // sig[0:32] is equal to field size
		},
		{ // 13
			privateKey: "",
			publicKey:  "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			aux:        "",
			message:    "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			signature:  "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
			valid:      false, // sig[32:64] is equal to curve order
		},
		{ // 14
			privateKey: "",
			publicKey:  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
			aux:        "",
			message:    "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			signature:  "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
			valid:      false, // public key is not a valid X coordinate because it exceeds the field size
		},
		{ // 15
			privateKey: "0340034003400340034003400340034003400340034003400340034003400340",
			publicKey:  "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
			aux:        "0000000000000000000000000000000000000000000000000000000000000000",
			message:    "",
			signature:  "71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63",
			valid:      true, // message of size 0 (added 2022-12)
		},
		{ // 16
			privateKey: "0340034003400340034003400340034003400340034003400340034003400340",
			publicKey:  "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
			aux:        "0000000000000000000000000000000000000000000000000000000000000000",
			message:    "11",
			signature:  "08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF",
			valid:      true, // message of size 1 (added 2022-12)
		},
		{ // 17
			privateKey: "0340034003400340034003400340034003400340034003400340034003400340",
			publicKey:  "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
			aux:        "0000000000000000000000000000000000000000000000000000000000000000",
			message:    "0102030405060708090A0B0C0D0E0F1011",
			signature:  "5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5",
			valid:      true, // message of size 17 (added 2022-12)
		},
		{ // 17
			privateKey: "0340034003400340034003400340034003400340034003400340034003400340",
			publicKey:  "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
			aux:        "0000000000000000000000000000000000000000000000000000000000000000",
			message:    "99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999",
			signature:  "403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367",
			valid:      true, // message of size 100 (added 2022-12)
		},
	}

	for i, v := range vectorData {
		data := v
		t.Run(fmt.Sprintf("vector test #%d", i), func(t *testing.T) {
			t.Parallel()

			if data.privateKey != "" {
				signatureBinActual, err := doTestSign(data.privateKey, data.message, data.aux)
				require.NoError(t, err)
				require.NotNil(t, signatureBinActual)

				signatureBinExpected, err := hex.DecodeString(data.signature)
				require.NoError(t, err)

				require.True(t, bytes.Equal(signatureBinExpected, signatureBinActual))
			}

			err := doTestVerify(data.publicKey, data.signature, data.message)
			if data.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func doTestSign(privateKeyString string, messageString string, auxString string) ([]byte, error) {
	privateKeyBin, err := hex.DecodeString(privateKeyString)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot decode private key")
	}

	bip340PrivateKey, err := unmarshalPrivateKey(privateKeyBin)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot unmarshal private key")
	}

	message, err := hex.DecodeString(messageString)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot decode message")
	}

	signer, _ := bip340.NewSigner(bip340PrivateKey)

	aux, err := hex.DecodeString(auxString)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot decode aux")
	}

	signature, err := signer.Sign(message, aux, crand.Reader)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot sign")
	}

	return marshalSignature(signature), nil
}

func doTestVerify(publicKeyString string, signatureString string, messageString string) error {
	publicKeyBin, err := hex.DecodeString(publicKeyString)
	if err != nil {
		return errs.WrapFailed(err, "cannot decode public key")
	}
	publicKey, err := unmarshalPublicKey(publicKeyBin)
	if err != nil {
		return errs.WrapFailed(err, "cannot unmarshal public key")
	}

	signatureBin, err := hex.DecodeString(signatureString)
	if err != nil {
		return errs.WrapFailed(err, "cannot decode signature")
	}
	signature, err := unmarshalSignature(signatureBin)
	if err != nil {
		return errs.WrapFailed(err, "cannot unmarshal signature")
	}

	message, err := hex.DecodeString(messageString)
	if err != nil {
		return errs.WrapFailed(err, "cannot decode message")
	}

	return bip340.Verify(publicKey, signature, message)
}

func Test_HappyPathBatchVerify(t *testing.T) {
	t.Parallel()
	message1 := []byte("something")
	message2 := []byte("bitcointranscation")
	curve := k256.NewCurve()

	t.Run(fmt.Sprintf("running the test for curve %s", curve.Name()), func(t *testing.T) {
		t.Parallel()

		sk1, err := curve.ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		aliceKey, err := bip340.NewPrivateKey(sk1)
		require.NoError(t, err)
		alice, _ := bip340.NewSigner(aliceKey)
		require.NotNil(t, alice)

		sk2, err := curve.ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		bobKey, err := bip340.NewPrivateKey(sk2)
		require.NoError(t, err)
		bob, _ := bip340.NewSigner(bobKey)
		require.NotNil(t, bob)

		signatureAlice, err := alice.Sign(message1, nil, crand.Reader)
		require.NoError(t, err)
		signatureBob, err := bob.Sign(message2, nil, crand.Reader)
		require.NoError(t, err)

		err = bip340.VerifyBatch([]*bip340.PublicKey{&aliceKey.PublicKey, &bobKey.PublicKey}, []*bip340.Signature{signatureAlice, signatureBob}, [][]byte{
			message1,
			message2,
		}, crand.Reader)
		require.NoError(t, err)
	})
}

func unmarshalPublicKey(input []byte) (*bip340.PublicKey, error) {
	if len(input) != base.FieldBytes {
		return nil, errs.NewSerialisation("invalid length")
	}
	p, err := decodePoint(input)
	if err != nil {
		return nil, errs.NewSerialisation("invalid point")
	}

	pk := &bip340.PublicKey{A: p}
	return pk, nil
}

func unmarshalPrivateKey(input []byte) (*bip340.PrivateKey, error) {
	if len(input) != base.FieldBytes {
		return nil, errs.NewSerialisation("invalid length")
	}
	curve := k256.NewCurve()
	k, err := curve.Scalar().SetBytes(input)
	if err != nil {
		return nil, errs.NewSerialisation("invalid scalar")
	}
	bigP, err := decodePoint(encodePoint(curve.ScalarBaseMult(k)))
	if err != nil {
		return nil, errs.NewSerialisation("invalid scalar")
	}

	sk := &bip340.PrivateKey{
		PublicKey: bip340.PublicKey{A: bigP},
		S:         k,
	}
	return sk, nil
}

func marshalSignature(signature *bip340.Signature) []byte {
	return bytes.Join([][]byte{encodePoint(signature.R), signature.S.Bytes()}, nil)
}

func unmarshalSignature(input []byte) (*bip340.Signature, error) {
	if len(input) != 64 {
		return nil, errs.NewSerialisation("invalid length")
	}

	r, err := decodePoint(input[:32])
	if err != nil {
		return nil, errs.NewSerialisation("invalid signature")
	}
	s, err := k256.NewCurve().Scalar().SetBytes(input[32:])
	if err != nil {
		return nil, errs.NewSerialisation("invalid signature")
	}

	signature := &bip340.Signature{
		R: r,
		S: s,
	}
	return signature, nil
}

func encodePoint(p curves.Point) []byte {
	return p.ToAffineCompressed()[1:]
}

func decodePoint(data []byte) (curves.Point, error) {
	curve := k256.NewCurve()
	p, err := curve.Point().FromAffineCompressed(bytes.Join([][]byte{{0x02}, data}, nil))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot decode point")
	}

	return p, nil
}
