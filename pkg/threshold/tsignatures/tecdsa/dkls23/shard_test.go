package dkls23_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/combinatorics"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	ttu "github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/bron-crypto/pkg/threshold/trusted_dealer"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/dkls23"
)

type testVector struct {
	name             string
	secretKey        string
	chainCode        string
	path             []uint32
	derivedSecretKey string
	derivedPublicKey string
	derivedChainCode string
}

var testVectors = []testVector{
	{
		name:             "BIP-32 Test Vector 2",
		secretKey:        "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
		chainCode:        "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
		path:             []uint32{0},
		derivedSecretKey: "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
		derivedPublicKey: "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea",
		derivedChainCode: "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c",
	},
	{
		name:             "xprv9zLF4ESSzRf9U2YEFf3xbCBAUCSKgNk5fmNC5iUuQvt184F2yRCAwagqrzhzHGvyHj4TYcTyZSL5evrictdCdg7AW8c8nKupxAgD167P9Cy",
		secretKey:        "8c434644ca68124063a5c34571c7bdc9f334a2e09f49298e19cf8c23f0e1581d",
		chainCode:        "ab8fa8ff999703249e61e88aa9a101d0efe7dc5b700c6c0029dccbd86aa3e9b7",
		path:             []uint32{100, 200, 0},
		derivedSecretKey: "86c7fde695abfcc0323d4360494ba9138e81ef307f12b1e89acd22d8356b1072",
		derivedPublicKey: "03b64ae8c5647a1d01a085316974be1632ffeb451d5a2298bcc4613612914a4d16",
		derivedChainCode: "1d70fe329866cd3e8b18e848ced43ef38b447b318672c9a5264c835df1025484",
	},
	{
		name:             "xprv9s21ZrQH143K4ARvDbwLA7DSyeaGNDZUBPJ78VikVRsHUPnHKs1BUDKMZMUozfhiN1efKmyG9NiPHuwokmDxbgEqQkNTBJZLmFUPeK4AkaC",
		secretKey:        "c74e37a52c02e342d57831cd7a5748f20d595226e754baf2a9cc8f98241bc950",
		chainCode:        "d3668e8886f98522b08f25fa355c33b26e91f2b7cef0964f08e8b43819a691c5",
		path:             []uint32{1, 2, 3, 9999},
		derivedSecretKey: "d71ab67d6458d55e8292ef9ed0fd5eda572125d45f5d36389ac9924820d66976",
		derivedPublicKey: "03a58a69fd51f9cb9b9d993dde981d47d9143e054c65074dc73053c7bf89d6db08",
		derivedChainCode: "09dcef0b0b9a8b648dc49d420c6633ba24e91780a2eb84ca3724a1911ed83379",
	},
	{
		name:             "xprv9s21ZrQH143K49wYHpjnF4MYkXqAWasddu7aWN4cu2v9r11K2EfExaGWRx9F3gYhi5dmcSCb76CVdTs2GkpJvujCLopu6PN4M4yizDXEuzH",
		secretKey:        "cedaf41a449cad7e3be23c5e85a065e60af7cc7281ed13fcea27dbcf6142e8bb",
		chainCode:        "d28da578c743f89fc0abe1c95d1cd65e01d3f7194929a4d054b4289064ec8d32",
		path:             []uint32{44, 0, 0, 0, 0},
		derivedSecretKey: "af814285d9bfbdad1391bae22c3793874b02f0f90777a7ee58d79ae151f7b418",
		derivedPublicKey: "0300720639160140e170c6dbd8497235313744fe0356edccec18c965583d051359",
		derivedChainCode: "075081949319a6d5292402916b8db3c624069250321a6c3e0243f29048695ddf",
	},
}

func Test_BIP32TestVectors(t *testing.T) {
	t.Parallel()

	const TH = 2
	const N = 3
	prng := crand.Reader
	curve := k256.NewCurve()

	for _, tv := range testVectors {
		t.Run(tv.name, func(t *testing.T) {
			t.Parallel()

			chainCodeHex := tv.chainCode
			chainCodeBytes, err := hex.DecodeString(chainCodeHex)
			require.NoError(t, err)
			chainCode := make([]byte, 32)
			copy(chainCode, chainCodeBytes)

			skHex := tv.secretKey
			skBytes, err := hex.DecodeString(skHex)
			require.NoError(t, err)
			secretKey, err := curve.ScalarField().Element().SetBytes(skBytes)
			require.NoError(t, err)

			identities, err := ttu.MakeDeterministicTestIdentities(N)
			require.NoError(t, err)
			protocol, err := ttu.MakeThresholdProtocol(curve, identities, TH)
			require.NoError(t, err)

			signingKeyShares, partialPublicKeys, err := trusted_dealer.Deal(protocol, secretKey, prng)
			require.NoError(t, err)
			shards := make([]*dkls23.Shard, N)
			for i, id := range identities {
				sks, _ := signingKeyShares.Get(id)
				ppk, _ := partialPublicKeys.Get(id)
				shards[i], err = dkls23.NewShard(protocol, sks, ppk)
				require.NoError(t, err)
			}

			derivedShards := make([]*dkls23.ExtendedShard, N)
			for i, shard := range shards {
				derivedShards[i] = deriveShard(t, shard, chainCode, tv.path)
				require.NoError(t, derivedShards[i].Validate(protocol))
			}

			expectedChildSecretKeyHex := tv.derivedSecretKey
			expectedChildPublicKeyHex := tv.derivedPublicKey
			expectedChildChainCodeHex := tv.derivedChainCode

			t.Run("child chain code is valid", func(t *testing.T) {
				t.Parallel()
				for _, derivedShard := range derivedShards {
					require.Equal(t, expectedChildChainCodeHex, hex.EncodeToString(derivedShard.ChainCodeBytes))
				}
			})

			t.Run("child public key is valid", func(t *testing.T) {
				t.Parallel()
				for _, derivedShard := range derivedShards {
					require.Equal(t, expectedChildPublicKeyHex, hex.EncodeToString(derivedShard.PublicKey().ToAffineCompressed()))
				}
			})

			t.Run("all child signing key shares interpolate to dlog of public key", func(t *testing.T) {
				t.Parallel()
				ns := make([]int, N)
				for i := range ns {
					ns[i] = i
				}

				sharingConfig := types.DeriveSharingConfig(hashset.NewHashableHashSet(identities...))
				combinations, err := combinatorics.Combinations(ns, TH)
				require.NoError(t, err)
				for _, combination := range combinations {
					shamirShares := make([]*shamir.Share, 0)
					for _, c := range combination {
						sharingId, exists := sharingConfig.Reverse().Get(identities[c])
						require.True(t, exists)

						share := derivedShards[c].SecretShare()
						shamirShares = append(shamirShares, &shamir.Share{
							Id:    sharingId,
							Value: share,
						})
					}

					shamirDealer, err := shamir.NewScheme(TH, N, curve)
					require.NoError(t, err)

					reconstructedPrivateKey, err := shamirDealer.Open(shamirShares...)
					require.NoError(t, err)
					require.Equal(t, expectedChildSecretKeyHex, hex.EncodeToString(reconstructedPrivateKey.Bytes()))

					derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
					aliceShard := derivedShards[0]
					require.True(t, aliceShard.PublicKey().Equal(derivedPublicKey))
				}
			})
		})
	}
}

func Test_Regression(t *testing.T) {
	// If this test fails, it means the way chain code is computed had changed.
	// This would be a breaking change rendering existing HD addresses unusable, leading potentially to loss of funds.
	// This test is here to ensure that the change is intentional and not a bug.
	t.Parallel()

	data := "[{\"SigningKeyShare\":{\"Share\":{\"type\":\"secp256k1\",\"bytes\":\"azwsGdlt5NxUymfIZUGz2MMl4m3p0sbF2y3UTY1LyGc=\"},\"PublicKey\":{\"type\":\"secp256k1\",\"bytes\":\"AwndnGkR9IOSZTDalVXXty810tE47mcBA8VdRF7+dyqT\"}},\"PublicKeyShares\":{\"PublicKey\":{\"type\":\"secp256k1\",\"bytes\":\"AwndnGkR9IOSZTDalVXXty810tE47mcBA8VdRF7+dyqT\"},\"Shares\":{\"1\":{\"type\":\"secp256k1\",\"bytes\":\"At9i/gV/p57AeMV4HAzUi01pikbkZPObZWeYC7SUDiQR\"},\"2\":{\"type\":\"secp256k1\",\"bytes\":\"AuU17o208rsvH2B+fV0v8px1afRivDxNztVTeG0k3Ki5\"},\"3\":{\"type\":\"secp256k1\",\"bytes\":\"At0hrC5bIte8HTnPn7fub2/APNi8DXAFqCFaPJAW+zgo\"}},\"FeldmanCommitmentVector\":[{\"type\":\"secp256k1\",\"bytes\":\"AwndnGkR9IOSZTDalVXXty810tE47mcBA8VdRF7+dyqT\"},{\"type\":\"secp256k1\",\"bytes\":\"A7Uys917ntpKn8rHYZXO+/bFnnWfqC0WKnjxe9NqOfXI\"}]}},{\"SigningKeyShare\":{\"Share\":{\"type\":\"secp256k1\",\"bytes\":\"SA81MYyOKq4+gcUuw8Puh0K3SociVJE8Wbx0SKvRk4c=\"},\"PublicKey\":{\"type\":\"secp256k1\",\"bytes\":\"AwndnGkR9IOSZTDalVXXty810tE47mcBA8VdRF7+dyqT\"}},\"PublicKeyShares\":{\"PublicKey\":{\"type\":\"secp256k1\",\"bytes\":\"AwndnGkR9IOSZTDalVXXty810tE47mcBA8VdRF7+dyqT\"},\"Shares\":{\"1\":{\"type\":\"secp256k1\",\"bytes\":\"At9i/gV/p57AeMV4HAzUi01pikbkZPObZWeYC7SUDiQR\"},\"2\":{\"type\":\"secp256k1\",\"bytes\":\"AuU17o208rsvH2B+fV0v8px1afRivDxNztVTeG0k3Ki5\"},\"3\":{\"type\":\"secp256k1\",\"bytes\":\"At0hrC5bIte8HTnPn7fub2/APNi8DXAFqCFaPJAW+zgo\"}},\"FeldmanCommitmentVector\":[{\"type\":\"secp256k1\",\"bytes\":\"AwndnGkR9IOSZTDalVXXty810tE47mcBA8VdRF7+dyqT\"},{\"type\":\"secp256k1\",\"bytes\":\"A7Uys917ntpKn8rHYZXO+/bFnnWfqC0WKnjxe9NqOfXI\"}]}},{\"SigningKeyShare\":{\"Share\":{\"type\":\"secp256k1\",\"bytes\":\"jmkjAiZNnwprEwpiBr95KkOUelSxUPxPXJ80Um7F/Uc=\"},\"PublicKey\":{\"type\":\"secp256k1\",\"bytes\":\"AwndnGkR9IOSZTDalVXXty810tE47mcBA8VdRF7+dyqT\"}},\"PublicKeyShares\":{\"PublicKey\":{\"type\":\"secp256k1\",\"bytes\":\"AwndnGkR9IOSZTDalVXXty810tE47mcBA8VdRF7+dyqT\"},\"Shares\":{\"1\":{\"type\":\"secp256k1\",\"bytes\":\"At9i/gV/p57AeMV4HAzUi01pikbkZPObZWeYC7SUDiQR\"},\"2\":{\"type\":\"secp256k1\",\"bytes\":\"AuU17o208rsvH2B+fV0v8px1afRivDxNztVTeG0k3Ki5\"},\"3\":{\"type\":\"secp256k1\",\"bytes\":\"At0hrC5bIte8HTnPn7fub2/APNi8DXAFqCFaPJAW+zgo\"}},\"FeldmanCommitmentVector\":[{\"type\":\"secp256k1\",\"bytes\":\"AwndnGkR9IOSZTDalVXXty810tE47mcBA8VdRF7+dyqT\"},{\"type\":\"secp256k1\",\"bytes\":\"A7Uys917ntpKn8rHYZXO+/bFnnWfqC0WKnjxe9NqOfXI\"}]}}]"
	var shards []*dkls23.Shard
	err := json.Unmarshal([]byte(data), &shards)
	require.NoError(t, err)

	require.Equal(t, "dc02983156a7f8d3529e80daa6ce58c72d811270d1ebf9e13ec814013a78fc7e", hex.EncodeToString(shards[0].ChainCode()))
	require.Equal(t, "dc02983156a7f8d3529e80daa6ce58c72d811270d1ebf9e13ec814013a78fc7e", hex.EncodeToString(shards[1].ChainCode()))
	require.Equal(t, "dc02983156a7f8d3529e80daa6ce58c72d811270d1ebf9e13ec814013a78fc7e", hex.EncodeToString(shards[2].ChainCode()))
}

func deriveShard(tb testing.TB, shard *dkls23.Shard, chainCode []byte, path []uint32) *dkls23.ExtendedShard {
	tb.Helper()
	result := &dkls23.ExtendedShard{
		Shard:          shard,
		ChainCodeBytes: chainCode,
	}

	for _, i := range path {
		var err error
		result, err = result.Derive(i)
		require.NoError(tb, err)
	}
	return result
}
