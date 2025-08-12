package mina_test

// import (
// 	"fmt"
// 	"testing"

// 	"github.com/bronlabs/bron-crypto/pkg/base/base58"
// 	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
// 	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/mina"
// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/require"
// )

// // Test vectors from https://github.com/o1-labs/o1js/blob/main/src/mina-signer/src/test-vectors/legacySignatures.ts
// var testVectorParams = struct {
// 	privateKey  base58.Base58
// 	publicKey   base58.Base58
// 	receiver    base58.Base58
// 	newDelegate base58.Base58
// }{
// 	privateKey:  "EKFKgDtU3rcuFTVSEpmpXSkukjmX4cKefYREi6Sdsk7E7wsT7KRw",
// 	publicKey:   "B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg",
// 	receiver:    "B62qrcFstkpqXww1EkSGrqMCwCNho86kuqBd4FrAAUsPxNKdiPzAUsy",
// 	newDelegate: "B62qkfHpLpELqpMK6ZvUTJ5wRqKDRF3UHyJ4Kv3FU79Sgs4qpBnx5RR",
// }

// type testVector struct {
// 	signature *signature
// }

// type signature struct {
// 	field  string
// 	scalar string
// }

// // Payment test vectors
// var paymentTests = []struct {
// 	amount  uint64
// 	fee     uint64
// 	nonce   uint32
// 	memo    string
// 	devnet  testVector
// 	mainnet testVector
// }{
// 	{
// 		amount: 42,
// 		fee:    3,
// 		nonce:  200,
// 		memo:   "this is a memo",
// 		devnet: testVector{
// 			signature: &signature{
// 				field:  "8120950991244270658590312510090196989287736939422559902738606305204468404423",
// 				scalar: "20435684186952094276538921729843968763934993686961133767619444982753499409888",
// 			},
// 		},
// 		mainnet: testVector{
// 			signature: &signature{
// 				field:  "15684602886486938845339686880556224615578410227520492332566162316562766628970",
// 				scalar: "18726235962149019201846207018134678049625398264201612011992805350228050313205",
// 			},
// 		},
// 	},
// 	{
// 		amount: 2048,
// 		fee:    15,
// 		nonce:  212,
// 		memo:   "this is not a pipe",
// 		devnet: testVector{
// 			signature: &signature{
// 				field:  "10463612449438270488269459889605175291654196122592241225893970752560988842952",
// 				scalar: "8194814724635187679647813389364090188027104716886424506108480365510180333553",
// 			},
// 		},
// 		mainnet: testVector{
// 			signature: &signature{
// 				field:  "25384077219847138156752903085673523046901005635315408695089224709277854013206",
// 				scalar: "21326116993375576140050987051970685478753413665962936578994845550034907963003",
// 			},
// 		},
// 	},
// 	{
// 		amount: 109,
// 		fee:    2001,
// 		nonce:  3050,
// 		memo:   "blessed be the geek",
// 		devnet: testVector{
// 			signature: &signature{
// 				field:  "26617663958942168588104436652358999702169155966619557809338920329907960429847",
// 				scalar: "17131677388583670943094306287078796185056479437290980364403388142164156047604",
// 			},
// 		},
// 		mainnet: testVector{
// 			signature: &signature{
// 				field:  "4087378788267193928211027982752764919410360860778087671253052747365568307445",
// 				scalar: "7298487835166710603130762501881886301626862170245654996402262766582842100002",
// 			},
// 		},
// 	},
// }

// // Delegation test vectors
// var delegationTests = []struct {
// 	fee     uint64
// 	nonce   uint32
// 	memo    string
// 	devnet  testVector
// 	mainnet testVector
// }{
// 	{
// 		fee:   3,
// 		nonce: 10,
// 		memo:  "more delegates, more fun",
// 		devnet: testVector{
// 			signature: &signature{
// 				field:  "9768542083149640447426194285602000048148701552664460913330924539777315355669",
// 				scalar: "13306299702344893269858992363339126128093333350546928455655659897348355180935",
// 			},
// 		},
// 		mainnet: testVector{
// 			signature: &signature{
// 				field:  "21937644604680608170217053686520363681591926176869177620701927968089063302772",
// 				scalar: "15674770093308750798159551895617738364856687141522681310577023124353387998206",
// 			},
// 		},
// 	},
// 	{
// 		fee:   10,
// 		nonce: 1000,
// 		memo:  "enough stake to kill a vampire",
// 		devnet: testVector{
// 			signature: &signature{
// 				field:  "2194300372006482912413024990637161763400053841840374002899640077265917329568",
// 				scalar: "23416340720237748925112270855927010142256271975330498514901735310450802969426",
// 			},
// 		},
// 		mainnet: testVector{
// 			signature: &signature{
// 				field:  "10925754845038919723542694113906174725062822644147295287657902994607912636607",
// 				scalar: "19148514796208589418440009161221234324406251470689394193049560863242128462072",
// 			},
// 		},
// 	},
// 	{
// 		fee:   8,
// 		nonce: 1010,
// 		memo:  "another memo",
// 		devnet: testVector{
// 			signature: &signature{
// 				field:  "9685736921829329487859222858260836774330589103618162468813203090920472811091",
// 				scalar: "23161709080072674756078732122438849127490361248615054674918997944726655315901",
// 			},
// 		},
// 		mainnet: testVector{
// 			signature: &signature{
// 				field:  "9055639605670749346601595775444750752713823110046054190997266020288294529188",
// 				scalar: "3853070942788752585343601038525178990686925093077993567960804028325301282959",
// 			},
// 		},
// 	},
// }

// // String message test vectors
// var stringTests = []struct {
// 	message string
// 	devnet  testVector
// 	mainnet testVector
// }{
// 	{
// 		message: "this is a test",
// 		devnet: testVector{
// 			signature: &signature{
// 				field:  "28372618008318639936114434703706072567084043853350576403130904109670269163835",
// 				scalar: "23161709080072674756078732122438849127490361248615054674918997944726655315901",
// 			},
// 		},
// 		mainnet: testVector{
// 			signature: &signature{
// 				field:  "19197333975827082698062030570386987458976589040862808950492850798662320401499",
// 				scalar: "3853070942788752585343601038525178990686925093077993567960804028325301282959",
// 			},
// 		},
// 	},
// 	{
// 		message: "this is only a test",
// 		devnet: testVector{
// 			signature: &signature{
// 				field:  "8492243648946017166465902588732269928004950635480721273023605551601688863206",
// 				scalar: "14286579509919556510950937271544018262675560854834296324593026094907904452672",
// 			},
// 		},
// 		mainnet: testVector{
// 			signature: &signature{
// 				field:  "1537922644639716999337529088028049536614226058850980308936293360640268859750",
// 				scalar: "4388269856574813896582426674199702491076503912287593607802790622925131968091",
// 			},
// 		},
// 	},
// 	{
// 		message: "if this had been an actual emergency...",
// 		devnet: testVector{
// 			signature: &signature{
// 				field:  "1486127254700368242813147247456536359752944799527873766090493137741035562862",
// 				scalar: "25518088706933817387609009131437999334839969836275494043850959665239467835405",
// 			},
// 		},
// 		mainnet: testVector{
// 			signature: &signature{
// 				field:  "18601427054193396897613547064436088864239935635243198488175520416028145228974",
// 				scalar: "25647598356573229982202601004334601586647042862413081271901459216223860882952",
// 			},
// 		},
// 	},
// }

// func TestTest(t *testing.T) {
// 	t.Parallel()
// 	_, err := mina.DecodePublicKey(testVectorParams.publicKey)
// 	require.NoError(t, err)
// 	// _, err = mina.DecodePrivateKey(testVectorParams.privateKey)
// 	// require.NoError(t, err)
// 	// _, err = mina.DecodePublicKey(testVectorParams.receiver)
// 	// require.NoError(t, err)
// 	// _, err = mina.DecodePublicKey(testVectorParams.newDelegate)
// 	// require.NoError(t, err)

// }

// func TestLegacySignatures(t *testing.T) {
// 	t.Parallel()
// 	publicKey, err := mina.DecodePublicKey(testVectorParams.publicKey)
// 	require.NoError(t, err)
// 	privateKey, err := mina.DecodePrivateKey(testVectorParams.privateKey)
// 	require.NoError(t, err)
// 	receiver, err := mina.DecodePublicKey(testVectorParams.receiver)
// 	require.NoError(t, err)
// 	newDelegate, err := mina.DecodePublicKey(testVectorParams.newDelegate)
// 	require.NoError(t, err)
// 	// Test payment signatures
// 	for i, test := range paymentTests {
// 		t.Run(fmt.Sprintf("payment_%d_devnet", i), func(t *testing.T) {
// 			msg := createPaymentMessage(publicKey, receiver, test.amount, test.fee, test.nonce, test.memo)
// 			scheme, err := mina.NewScheme(mina.TestNet, privateKey)
// 			require.NoError(t, err)

// 			signer, err := scheme.Signer(privateKey)
// 			require.NoError(t, err)
// 			sig, err := signer.Sign(msg)
// 			require.NoError(t, err)

// 			actualSignatureIsAsExpected(t, sig, test.devnet.signature)

// 			// Verify signature
// 			verifier, err := scheme.Verifier()
// 			require.NoError(t, err)
// 			err = verifier.Verify(sig, publicKey, msg)
// 			assert.NoError(t, err)
// 		})

// 		t.Run(fmt.Sprintf("payment_%d_mainnet", i), func(t *testing.T) {
// 			msg := createPaymentMessage(publicKey, receiver, test.amount, test.fee, test.nonce, test.memo)
// 			scheme, err := mina.NewScheme(mina.MainNet, privateKey)
// 			require.NoError(t, err)

// 			signer, err := scheme.Signer(privateKey)
// 			require.NoError(t, err)
// 			sig, err := signer.Sign(msg)
// 			require.NoError(t, err)

// 			actualSignatureIsAsExpected(t, sig, test.mainnet.signature)

// 			// Verify signature
// 			verifier, err := scheme.Verifier()
// 			require.NoError(t, err)
// 			err = verifier.Verify(sig, publicKey, msg)
// 			assert.NoError(t, err)
// 		})
// 	}

// 	// Test delegation signatures
// 	for i, test := range delegationTests {
// 		t.Run(fmt.Sprintf("delegation_%d_devnet", i), func(t *testing.T) {
// 			msg := createDelegationMessage(publicKey, newDelegate, test.fee, test.nonce, test.memo)
// 			scheme, err := mina.NewScheme(mina.TestNet, privateKey)
// 			require.NoError(t, err)

// 			signer, err := scheme.Signer(privateKey)
// 			require.NoError(t, err)
// 			sig, err := signer.Sign(msg)
// 			require.NoError(t, err)

// 			actualSignatureIsAsExpected(t, sig, test.devnet.signature)

// 			// Verify signature
// 			verifier, err := scheme.Verifier()
// 			require.NoError(t, err)
// 			err = verifier.Verify(sig, publicKey, msg)
// 			assert.NoError(t, err)
// 		})

// 		t.Run(fmt.Sprintf("delegation_%d_mainnet", i), func(t *testing.T) {
// 			msg := createDelegationMessage(publicKey, newDelegate, test.fee, test.nonce, test.memo)
// 			scheme, err := mina.NewScheme(mina.MainNet, privateKey)
// 			require.NoError(t, err)

// 			signer, err := scheme.Signer(privateKey)
// 			require.NoError(t, err)
// 			sig, err := signer.Sign(msg)
// 			require.NoError(t, err)

// 			actualSignatureIsAsExpected(t, sig, test.mainnet.signature)

// 			// Verify signature
// 			verifier, err := scheme.Verifier()
// 			require.NoError(t, err)
// 			err = verifier.Verify(sig, publicKey, msg)
// 			assert.NoError(t, err)
// 		})
// 	}

// 	// Test string message signatures
// 	for i, test := range stringTests {
// 		t.Run(fmt.Sprintf("string_%d_devnet", i), func(t *testing.T) {
// 			msg := new(mina.ROInput).Init()
// 			msg.AddString(test.message)

// 			scheme, err := mina.NewScheme(mina.TestNet, privateKey)
// 			require.NoError(t, err)

// 			signer, err := scheme.Signer(privateKey)
// 			require.NoError(t, err)
// 			sig, err := signer.Sign(msg)
// 			require.NoError(t, err)

// 			actualSignatureIsAsExpected(t, sig, test.devnet.signature)

// 			// Verify signature
// 			verifier, err := scheme.Verifier()
// 			require.NoError(t, err)
// 			err = verifier.Verify(sig, publicKey, msg)
// 			assert.NoError(t, err)
// 		})

// 		t.Run(fmt.Sprintf("string_%d_mainnet", i), func(t *testing.T) {
// 			msg := new(mina.ROInput).Init()
// 			msg.AddString(test.message)

// 			scheme, err := mina.NewScheme(mina.MainNet, privateKey)
// 			require.NoError(t, err)

// 			signer, err := scheme.Signer(privateKey)
// 			require.NoError(t, err)
// 			sig, err := signer.Sign(msg)
// 			require.NoError(t, err)

// 			actualSignatureIsAsExpected(t, sig, test.mainnet.signature)

// 			// Verify signature
// 			verifier, err := scheme.Verifier()
// 			require.NoError(t, err)
// 			err = verifier.Verify(sig, publicKey, msg)
// 			assert.NoError(t, err)
// 		})
// 	}
// }

// // Helper functions to create payment and delegation messages
// func createPaymentMessage(source, receiver *mina.PublicKey, amount, fee uint64, nonce uint32, memo string) *mina.ROInput {
// 	msg := new(mina.ROInput).Init()
// 	baseField := pasta.NewPallasBaseField()

// 	// Add payment fields in the correct order
// 	zeroField := baseField.Zero()
// 	msg.AddFields(zeroField) // tag (0 for payment)

// 	// Add source public key coordinates
// 	msg.AddFields(source.V.AffineX(), source.V.AffineY())

// 	// Add receiver public key coordinates
// 	msg.AddFields(receiver.V.AffineX(), receiver.V.AffineY())

// 	// Add amount as field element
// 	amountField := baseField.FromUint64(amount)
// 	msg.AddFields(amountField)

// 	// Add fee as field element
// 	feeField := baseField.FromUint64(fee)
// 	msg.AddFields(feeField)

// 	// Add nonce as field element
// 	nonceField := baseField.FromUint64(uint64(nonce))
// 	msg.AddFields(nonceField)

// 	// Add valid_until (None = 0)
// 	msg.AddFields(zeroField)

// 	// Add memo as string
// 	msg.AddString(memo)

// 	return msg
// }

// func createDelegationMessage(source, newDelegate *mina.PublicKey, fee uint64, nonce uint32, memo string) *mina.ROInput {
// 	msg := new(mina.ROInput).Init()
// 	baseField := pasta.NewPallasBaseField()

// 	// Add delegation fields in the correct order
// 	oneField := baseField.One()
// 	msg.AddFields(oneField) // tag (1 for delegation)

// 	// Add source public key coordinates
// 	msg.AddFields(source.V.AffineX(), source.V.AffineY())

// 	// Add new delegate public key coordinates
// 	msg.AddFields(newDelegate.V.AffineX(), newDelegate.V.AffineY())

// 	// Add fee as field element
// 	feeField := baseField.FromUint64(fee)
// 	msg.AddFields(feeField)

// 	// Add nonce as field element
// 	nonceField := baseField.FromUint64(uint64(nonce))
// 	msg.AddFields(nonceField)

// 	// Add valid_until (None = 0)
// 	zeroField := baseField.Zero()
// 	msg.AddFields(zeroField)

// 	// Add memo as string
// 	msg.AddString(memo)

// 	return msg
// }

// func actualSignatureIsAsExpected(t testing.TB, actual *mina.Signature, expected *signature) {
// 	t.Helper()
// 	assert.Equal(t, expected.field, actual.R.AffineX().String(), "R field does not match expected value")
// 	assert.Equal(t, expected.scalar, actual.S.String(), "S scalar does not match expected value")
// }
