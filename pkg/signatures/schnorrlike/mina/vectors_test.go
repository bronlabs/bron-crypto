package mina_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/base58"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/mina"
)

// Test vectors from https://github.com/o1-labs/o1js/blob/main/src/mina-signer/src/test-vectors/legacySignatures.ts
var testVectorParams = struct {
	privateKey  base58.Base58
	publicKey   base58.Base58
	receiver    base58.Base58
	newDelegate base58.Base58
}{
	privateKey:  "EKFKgDtU3rcuFTVSEpmpXSkukjmX4cKefYREi6Sdsk7E7wsT7KRw",
	publicKey:   "B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg",
	receiver:    "B62qrcFstkpqXww1EkSGrqMCwCNho86kuqBd4FrAAUsPxNKdiPzAUsy",
	newDelegate: "B62qkfHpLpELqpMK6ZvUTJ5wRqKDRF3UHyJ4Kv3FU79Sgs4qpBnx5RR",
}

type testVector struct {
	signature *signature
}

type signature struct {
	field  string
	scalar string
}

// Payment test vectors
var paymentTests = []struct {
	amount     uint64
	fee        uint64
	nonce      uint32
	validUntil uint32
	memo       string
	devnet     testVector
	mainnet    testVector
}{
	{
		amount:     42,
		fee:        3,
		nonce:      200,
		validUntil: 10000,
		memo:       "this is a memo",
		devnet: testVector{
			signature: &signature{
				field:  "3925887987173883783388058255268083382298769764463609405200521482763932632383",
				scalar: "445615701481226398197189554290689546503290167815530435382795701939759548136",
			},
		},
		mainnet: testVector{
			signature: &signature{
				field:  "2290465734865973481454975811990842289349447524565721011257265781466170720513",
				scalar: "174718295375042423373378066296864207343460524320417038741346483351503066865",
			},
		},
	},
	{
		amount:     2048,
		fee:        15,
		nonce:      212,
		validUntil: 305,
		memo:       "this is not a pipe",
		devnet: testVector{
			signature: &signature{
				field:  "11838925242791061185900891854974280922359055483441419242429642295065318643984",
				scalar: "5057044820006008308046028014628135487302791372585541488835641418654652928805",
			},
		},
		mainnet: testVector{
			signature: &signature{
				field:  "3338221378196321618737404652850173545830741260219426985985110494623248154796",
				scalar: "13582570889626737053936904045130069988029386067840542224501137534361543053466",
			},
		},
	},
	{
		amount:     109,
		fee:        2001,
		nonce:      3050,
		validUntil: 9000,
		memo:       "blessed be the geek",
		devnet: testVector{
			signature: &signature{
				field:  "13570419670106759824217358880396743605262660069048455950202130815805728575057",
				scalar: "2256128221267944805514947515637443480133552241968312777663034361688965989223",
			},
		},
		mainnet: testVector{
			signature: &signature{
				field:  "24977166875850415387591601609169744956874881328889802588427412550673368014171",
				scalar: "8818176737844714163963728742657256399283959917269715546724011366788373936767",
			},
		},
	},
}

// Delegation test vectors
var delegationTests = []struct {
	fee        uint64
	nonce      uint32
	validUntil uint32
	memo       string
	devnet     testVector
	mainnet    testVector
}{
	{
		fee:        3,
		nonce:      10,
		validUntil: 4000,
		memo:       "more delegates, more fun",
		devnet: testVector{
			signature: &signature{
				field:  "18603328765572408555868399359399411973012220541556204196884026585115374044583",
				scalar: "17076342019359061119005549736934690084415105419939473687106079907606137611470",
			},
		},
		mainnet: testVector{
			signature: &signature{
				field:  "18549185720796945285997801022505868190780742636917696085321477383695464941808",
				scalar: "9968155560235917784839059154575307851833761552720670659405850314060739412758",
			},
		},
	},
	{
		fee:        10,
		nonce:      1000,
		validUntil: 8192,
		memo:       "enough stake to kill a vampire",
		devnet: testVector{
			signature: &signature{
				field:  "1786373894608285187089973929748850875336413409295396991315429715474432640801",
				scalar: "10435258496141097615588833319454104720521911644724923418749752896069542389757",
			},
		},
		mainnet: testVector{
			signature: &signature{
				field:  "27435277901837444378602251759261698832749786010721792798570593506489878524054",
				scalar: "5303814070856978976450674139278204752713705309497875510553816988969674317908",
			},
		},
	},
	{
		fee:        8,
		nonce:      1010,
		validUntil: 100000,
		memo:       "another memo",
		devnet: testVector{
			signature: &signature{
				field:  "11710586766419351067338319607483640291676872446372400739329190129174446858072",
				scalar: "21663533922934564101122062377096487451020504743791218020915919810997397884837",
			},
		},
		mainnet: testVector{
			signature: &signature{
				field:  "18337925798749632162999573213504280894403810378974021233452576035581180265108",
				scalar: "17033350386680878193188260707518516061312646961349757526930471244219909355133",
			},
		},
	},
}

// String message test vectors
var stringTests = []struct {
	message string
	devnet  testVector
	mainnet testVector
}{
	{
		message: "this is a test",
		devnet: testVector{
			signature: &signature{
				field:  "11583775536286847540414661987230057163492736306749717851628536966882998258109",
				scalar: "14787360096063782022566783796923142259879388947509616216546009448340181956495",
			},
		},
		mainnet: testVector{
			signature: &signature{
				field:  "15321026181887258084717253351692625217563887132804118766475695975434200286072",
				scalar: "27693688834009297019754701709097142916828669707451033859732637861400085816575",
			},
		},
	},
	{
		message: "this is only a test",
		devnet: testVector{
			signature: &signature{
				field:  "24809097509137086694730479515383937245108109696879845335879579016397403384488",
				scalar: "23723859937408726087117568974923795978435877847592289069941156359435022279156",
			},
		},
		mainnet: testVector{
			signature: &signature{
				field:  "7389839717736616673468176670823346848621475008909123730960586617430930011362",
				scalar: "16812002169649926565884427604872242188288298244442130642661893463581998776079",
			},
		},
	},
	{
		message: "if this had been an actual emergency...",
		devnet: testVector{
			signature: &signature{
				field:  "23803497755408154859878117448681790665144834176143832235351783889976460433296",
				scalar: "21219917886278462345652813021708727397787183083051040637716760620250038837684",
			},
		},
		mainnet: testVector{
			signature: &signature{
				field:  "25237307917208237775896283358517786348974681409860182331969894401303358790178",
				scalar: "1498643894425942815773348600211341433686244249442354387056510209608647184582",
			},
		},
	},
}

func TestLegacySignatures(t *testing.T) {
	t.Parallel()

	publicKey, err := mina.DecodePublicKey(testVectorParams.publicKey)
	require.NoError(t, err)
	privateKey, err := mina.DecodePrivateKey(testVectorParams.privateKey)
	require.NoError(t, err)
	receiver, err := mina.DecodePublicKey(testVectorParams.receiver)
	require.NoError(t, err)
	newDelegate, err := mina.DecodePublicKey(testVectorParams.newDelegate)
	require.NoError(t, err)
	// Test payment signatures
	for i, test := range paymentTests {
		t.Run(fmt.Sprintf("payment_%d_devnet", i), func(t *testing.T) {
			msg, err := mina.NewPaymentMessage(publicKey, receiver, test.amount, test.fee, test.nonce, test.validUntil, test.memo)
			require.NoError(t, err)
			scheme, err := mina.NewScheme(mina.TestNet, privateKey)
			require.NoError(t, err)

			signer, err := scheme.Signer(privateKey)
			require.NoError(t, err)
			sig, err := signer.Sign(msg)
			require.NoError(t, err)

			actualSignatureIsAsExpected(t, sig, test.devnet.signature)

			// Verify signature
			verifier, err := scheme.Verifier()
			require.NoError(t, err)
			err = verifier.Verify(sig, publicKey, msg)
			require.NoError(t, err)
		})

		t.Run(fmt.Sprintf("payment_%d_mainnet", i), func(t *testing.T) {
			msg, err := mina.NewPaymentMessage(publicKey, receiver, test.amount, test.fee, test.nonce, test.validUntil, test.memo)
			require.NoError(t, err)
			scheme, err := mina.NewScheme(mina.MainNet, privateKey)
			require.NoError(t, err)

			signer, err := scheme.Signer(privateKey)
			require.NoError(t, err)
			sig, err := signer.Sign(msg)
			require.NoError(t, err)

			actualSignatureIsAsExpected(t, sig, test.mainnet.signature)

			// Verify signature
			verifier, err := scheme.Verifier()
			require.NoError(t, err)
			err = verifier.Verify(sig, publicKey, msg)
			require.NoError(t, err)
		})
	}

	// Test delegation signatures
	for i, test := range delegationTests {
		t.Run(fmt.Sprintf("delegation_%d_devnet", i), func(t *testing.T) {
			msg, err := mina.NewDelegationMessage(publicKey, newDelegate, test.fee, test.nonce, test.validUntil, test.memo)
			require.NoError(t, err)
			scheme, err := mina.NewScheme(mina.TestNet, privateKey)
			require.NoError(t, err)

			signer, err := scheme.Signer(privateKey)
			require.NoError(t, err)
			sig, err := signer.Sign(msg)
			require.NoError(t, err)

			actualSignatureIsAsExpected(t, sig, test.devnet.signature)

			// Verify signature
			verifier, err := scheme.Verifier()
			require.NoError(t, err)
			err = verifier.Verify(sig, publicKey, msg)
			require.NoError(t, err)
		})

		t.Run(fmt.Sprintf("delegation_%d_mainnet", i), func(t *testing.T) {
			msg, err := mina.NewDelegationMessage(publicKey, newDelegate, test.fee, test.nonce, test.validUntil, test.memo)
			require.NoError(t, err)
			scheme, err := mina.NewScheme(mina.MainNet, privateKey)
			require.NoError(t, err)

			signer, err := scheme.Signer(privateKey)
			require.NoError(t, err)
			sig, err := signer.Sign(msg)
			require.NoError(t, err)

			actualSignatureIsAsExpected(t, sig, test.mainnet.signature)

			// Verify signature
			verifier, err := scheme.Verifier()
			require.NoError(t, err)
			err = verifier.Verify(sig, publicKey, msg)
			require.NoError(t, err)
		})
	}

	// Test string message signatures
	for i, test := range stringTests {
		t.Run(fmt.Sprintf("string_%d_devnet", i), func(t *testing.T) {
			msg := new(mina.ROInput).Init()
			msg.AddString(test.message)

			scheme, err := mina.NewScheme(mina.TestNet, privateKey)
			require.NoError(t, err)

			signer, err := scheme.Signer(privateKey)
			require.NoError(t, err)
			sig, err := signer.Sign(msg)
			require.NoError(t, err)

			actualSignatureIsAsExpected(t, sig, test.devnet.signature)

			// Verify signature
			verifier, err := scheme.Verifier()
			require.NoError(t, err)
			err = verifier.Verify(sig, publicKey, msg)
			require.NoError(t, err)
		})

		t.Run(fmt.Sprintf("string_%d_mainnet", i), func(t *testing.T) {
			msg := new(mina.ROInput).Init()
			msg.AddString(test.message)

			scheme, err := mina.NewScheme(mina.MainNet, privateKey)
			require.NoError(t, err)

			signer, err := scheme.Signer(privateKey)
			require.NoError(t, err)
			sig, err := signer.Sign(msg)
			require.NoError(t, err)

			actualSignatureIsAsExpected(t, sig, test.mainnet.signature)

			// Verify signature
			verifier, err := scheme.Verifier()
			require.NoError(t, err)
			err = verifier.Verify(sig, publicKey, msg)
			require.NoError(t, err)
		})
	}
}

func actualSignatureIsAsExpected(tb testing.TB, actual *mina.Signature, expected *signature) {
	tb.Helper()
	rx, err := actual.R.AffineX()
	require.NoError(tb, err)
	require.Equal(tb, expected.field, rx.String(), "R field does not match expected value")
	require.Equal(tb, expected.scalar, actual.S.String(), "S scalar does not match expected value")
}
