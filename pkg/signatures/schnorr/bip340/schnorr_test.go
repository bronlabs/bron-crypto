package bip340_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/signatures/schnorr/bip340"
)

func TestVector(t *testing.T) {
	type TestVectorData struct {
		SecretKey string
		PublicKey string
		Aux       string
		Message   string
		Signature string
		Valid     bool
	}
	vectorData := []TestVectorData{
		{
			SecretKey: "0000000000000000000000000000000000000000000000000000000000000003",
			PublicKey: "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
			Aux:       "0000000000000000000000000000000000000000000000000000000000000000",
			Message:   "0000000000000000000000000000000000000000000000000000000000000000",
			Signature: "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
			Valid:     true,
		},
		{
			SecretKey: "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
			PublicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			Aux:       "0000000000000000000000000000000000000000000000000000000000000001",
			Message:   "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			Signature: "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
			Valid:     true,
		},
		{
			SecretKey: "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
			PublicKey: "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
			Aux:       "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
			Message:   "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
			Signature: "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
			Valid:     true,
		},
		{
			SecretKey: "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
			PublicKey: "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
			Aux:       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			Message:   "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			Signature: "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
			Valid:     true,
		},
		{
			SecretKey: "",
			PublicKey: "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
			Aux:       "",
			Message:   "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
			Signature: "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
			Valid:     true,
		},
		{
			SecretKey: "",
			PublicKey: "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
			Aux:       "",
			Message:   "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			Signature: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
			Valid:     false, // public key not on the curve
		},
		{
			SecretKey: "",
			PublicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			Aux:       "",
			Message:   "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			Signature: "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
			Valid:     false, // has_even_y(R) is false
		},
		{
			SecretKey: "",
			PublicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			Aux:       "",
			Message:   "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			Signature: "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD",
			Valid:     false, // negated message
		},
		{
			SecretKey: "",
			PublicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			Aux:       "",
			Message:   "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			Signature: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6",
			Valid:     false, // negated s value
		},
		{
			SecretKey: "",
			PublicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			Aux:       "",
			Message:   "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			Signature: "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051",
			Valid:     false, // sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 0
		},
		{
			SecretKey: "",
			PublicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			Aux:       "",
			Message:   "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			Signature: "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197",
			Valid:     false, // sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 1
		},
		{
			SecretKey: "",
			PublicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			Aux:       "",
			Message:   "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			Signature: "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
			Valid:     false, // sig[0:32] is not an X coordinate on the curve
		},
		{
			SecretKey: "",
			PublicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			Aux:       "",
			Message:   "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			Signature: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
			Valid:     false, // sig[0:32] is equal to field size
		},
		{
			SecretKey: "",
			PublicKey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
			Aux:       "",
			Message:   "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			Signature: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
			Valid:     false, // sig[32:64] is equal to curve order
		},
	}

	for i, v := range vectorData {
		if v.SecretKey == "" {
			continue
		}
		t.Run(fmt.Sprintf("vector test #%d", i), func(t *testing.T) {
			cipherSuite := &integration.CipherSuite{
				Curve: k256.New(),
				Hash:  sha3.New256,
			}
			d, _ := hex.DecodeString(v.SecretKey)
			secret, _ := k256.New().Scalar().SetBytes(d)
			signer, err := bip340.NewSigner(cipherSuite, secret)
			require.NoError(t, err)
			require.NotNil(t, signer)
			require.NotNil(t, signer.PublicKey)

			aux, _ := hex.DecodeString(v.Aux)
			msg, _ := hex.DecodeString(v.Message)
			signature, err := signer.Sign(msg, aux)
			require.NoError(t, err)
			require.Equal(t, strings.ToLower(v.Signature), hex.EncodeToString(append(signature.R.Bytes(), signature.S.Bytes()...)))

			err = bip340.Verify(signer.PublicKey, msg, signature)
			require.NoError(t, err)
		})
	}
	for i, v := range vectorData {
		if v.SecretKey != "" {
			continue
		}
		t.Run(fmt.Sprintf("vector signature test #%d", i), func(t *testing.T) {
			curve := k256.New()
			publicKey, _ := hex.DecodeString(v.PublicKey)
			Y, err := curve.Point().FromAffineCompressed(append([]byte{0x02}, publicKey...))
			require.NoError(t, err)
			signature, _ := hex.DecodeString(v.Signature)
			msg, _ := hex.DecodeString(v.Message)
			pk := bip340.PublicKey{
				Curve: curve,
				Y:     Y,
			}
			R, _ := curve.Scalar().SetBytes(signature[:32])
			S, _ := curve.Scalar().SetBytes(signature[32:64])
			err = bip340.Verify(&pk, msg, &bip340.Signature{
				R: R,
				S: S,
			})
			if v.Valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}

	vectorData = []TestVectorData{
		{
			SecretKey: "",
			PublicKey: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
			Aux:       "",
			Message:   "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
			Signature: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
			Valid:     false, // public key is not a valid X coordinate because it exceeds the field size
		},
	}
	for i, v := range vectorData {
		if v.SecretKey != "" {
			continue
		}
		t.Run(fmt.Sprintf("vector pubkey test #%d", i), func(t *testing.T) {
			curve := k256.New()
			publicKey, _ := hex.DecodeString(v.PublicKey)
			_, err := curve.Point().FromAffineCompressed(append([]byte{0x02}, publicKey...))
			require.Error(t, err)
		})
	}
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	r := crand.Reader
	message := make([]byte, 32)
	r.Read(message)
	hs := []func() hash.Hash{
		sha3.New256,
		sha512.New,
	}
	for _, curve := range []curves.Curve{k256.New()} {
		for i, h := range hs {
			boundedCurve := curve
			boundedH := h
			t.Run(fmt.Sprintf("running the test for curve %s and hash no %d", boundedCurve.Name(), i), func(t *testing.T) {
				t.Parallel()
				cipherSuite := &integration.CipherSuite{
					Curve: boundedCurve,
					Hash:  boundedH,
				}
				d, _ := hex.DecodeString("3ceae3c1107ec58d28895bec5e5a6cd20b629fbd97f8002afcab6b9de7bd7259")
				secret, _ := curve.Scalar().SetBytes(d)
				signer, err := bip340.NewSigner(cipherSuite, secret)
				require.NoError(t, err)
				require.NotNil(t, signer)
				require.NotNil(t, signer.PublicKey)

				aux := make([]byte, 32)
				r.Read(aux)
				signature, err := signer.Sign(message, aux)
				require.NoError(t, err)

				err = bip340.Verify(signer.PublicKey, message, signature)
				require.NoError(t, err)
			})
		}
	}
}

func Test_HappyPath_BatchVerify(t *testing.T) {
	t.Parallel()
	message1 := []byte("something")
	message2 := []byte("bitcointranscation")
	hs := []func() hash.Hash{
		sha3.New256,
		sha512.New,
	}
	for i, h := range hs {
		boundedCurve := k256.New()
		boundedH := h
		t.Run(fmt.Sprintf("running the test for curve %s and hash no %d", boundedCurve.Name(), i), func(t *testing.T) {
			t.Parallel()
			cipherSuite := &integration.CipherSuite{
				Curve: boundedCurve,
				Hash:  boundedH,
			}
			alice, err := bip340.NewSigner(cipherSuite, boundedCurve.Scalar().Random(crand.Reader))
			require.NoError(t, err)
			require.NotNil(t, alice)
			require.NotNil(t, alice.PublicKey)
			bob, err := bip340.NewSigner(cipherSuite, boundedCurve.Scalar().Random(crand.Reader))
			require.NoError(t, err)
			require.NotNil(t, bob)
			require.NotNil(t, bob.PublicKey)

			signatureAlice, err := alice.Sign(message1, nil)
			require.NoError(t, err)
			signatureBob, err := bob.Sign(message2, nil)
			require.NoError(t, err)

			err = bip340.BatchVerify(nil, cipherSuite, []*bip340.PublicKey{alice.PublicKey, bob.PublicKey}, [][]byte{
				message1,
				message2,
			}, []*bip340.Signature{signatureAlice, signatureBob})
			require.NoError(t, err)
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping test in short mode.")
	}
	batchSize := 10000
	boundedCurve := k256.New()
	boundedH := sha3.New256
	cipherSuite := &integration.CipherSuite{
		Curve: boundedCurve,
		Hash:  boundedH,
	}
	aux := make([]byte, 32)
	_, _ = crand.Read(aux)
	signer, _ := bip340.NewSigner(cipherSuite, boundedCurve.Scalar().Random(crand.Reader))
	messages := make([][]byte, batchSize)
	pubkeys := make([]*bip340.PublicKey, batchSize)
	signatures := make([]*bip340.Signature, batchSize)
	for i := 0; i < batchSize; i++ {
		message := make([]byte, 32)
		_, _ = crand.Read(message)
		signature, _ := signer.Sign(message, nil)
		messages[i] = message
		pubkeys[i] = signer.PublicKey
		signatures[i] = signature
	}
	b.Run("SingleVerify", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			for i := 0; i < batchSize; i++ {
				err := bip340.Verify(pubkeys[i], messages[i], signatures[i])
				if err != nil {
					b.Fatal(err)
				}
			}
		}
	})
	b.Run("BatchVerify", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			err := bip340.BatchVerify(nil, cipherSuite, pubkeys, messages, signatures)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func Test_CanJsonMarshalAndUnmarshal(t *testing.T) {
	t.Parallel()
	message := []byte("something")
	cipherSuite := &integration.CipherSuite{
		Curve: k256.New(),
		Hash:  sha512.New,
	}
	signer, err := bip340.NewSigner(cipherSuite, k256.New().Scalar().Random(crand.Reader))
	require.NoError(t, err)
	require.NotNil(t, signer)
	require.NotNil(t, signer.PublicKey)

	signature, err := signer.Sign(message, nil)
	require.NoError(t, err)

	marshalled, err := json.Marshal(signature)
	require.NoError(t, err)
	require.Greater(t, len(marshalled), 0)

	var unmarshaled *bip340.Signature
	err = json.Unmarshal(marshalled, &unmarshaled)
	require.NoError(t, err)
	require.Equal(t, signature, unmarshaled)
}
