package lindell17_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/lindell17"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/trusted_dealer"
)

func Test_Bip32DeriveShardTestVector2(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	th := 2
	n := 3

	chainCodeHex := "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689"
	chainCodeBytes, err := hex.DecodeString(chainCodeHex)
	require.NoError(t, err)
	chainCode := make([]byte, 32)
	copy(chainCode, chainCodeBytes)

	skHex := "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e"
	skBytes, err := hex.DecodeString(skHex)
	require.NoError(t, err)
	secretKey, err := curve.ScalarField().Element().SetBytes(skBytes)
	require.NoError(t, err)

	identities, err := testutils.MakeDeterministicTestIdentities(n)
	require.NoError(t, err)
	sort.Sort(types.ByPublicKey(identities))

	protocol, err := testutils.MakeThresholdProtocol(curve, identities, th)
	require.NoError(t, err)

	parentShards, err := trusted_dealer.Deal(protocol, secretKey, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, parentShards)
	require.Equal(t, parentShards.Size(), int(protocol.TotalParties()))

	shards := hashmap.NewHashableHashMap[types.IdentityKey, *lindell17.ExtendedShard]()
	for id, parentShard := range parentShards.Iter() {
		shard, err := parentShard.DeriveWithChainCode(chainCode, 0)
		require.NoError(t, err)
		shards.Put(id, shard)
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	expectedChildSecretKeyHex := "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e"
	expectedChildPublicKeyHex := "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea"
	expectedChildChainCodeHex := "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c"

	t.Run("all chain code are valid", func(t *testing.T) {
		t.Parallel()
		for _, value := range shards.Iter() {
			require.Equal(t, expectedChildChainCodeHex, hex.EncodeToString(value.ChainCodeBytes))
		}
	})

	t.Run("all signing key shares are valid", func(t *testing.T) {
		t.Parallel()
		for _, value := range shards.Iter() {
			err = value.Shard.SigningKeyShare.Validate(protocol)
			require.NoError(t, err)
		}
	})

	t.Run("all partial public keys are valid", func(t *testing.T) {
		t.Parallel()
		for _, value := range shards.Iter() {
			err = value.Shard.PublicKeyShares.Validate(protocol)
			require.NoError(t, err)
			require.Equal(t, expectedChildPublicKeyHex, hex.EncodeToString(value.Shard.PublicKeyShares.PublicKey.ToAffineCompressed()))
		}
	})

	t.Run("all public keys are the same", func(t *testing.T) {
		t.Parallel()
		publicKeys := map[string]bool{}
		for _, value := range shards.Iter() {
			if _, exists := publicKeys[hex.EncodeToString(value.Shard.SigningKeyShare.PublicKey.ToAffineCompressed())]; !exists {
				publicKeys[hex.EncodeToString(value.Shard.SigningKeyShare.PublicKey.ToAffineCompressed())] = true
			}
		}
		require.Len(t, publicKeys, 1)
	})

	t.Run("all signing key shares interpolate to dlog of public key", func(t *testing.T) {
		t.Parallel()

		shamirDealer, err := shamir.NewScheme(uint(th), uint(n), curve)
		require.NoError(t, err)
		require.NotNil(t, shamirDealer)
		shamirShares := make([]*shamir.Share, n)
		for i := 0; i < n; i++ {
			thisShard, exists := shards.Get(identities[i])
			require.True(t, exists)
			shamirShares[i] = &shamir.Share{
				Id:    types.SharingID(i + 1),
				Value: thisShard.Shard.SigningKeyShare.Share,
			}
		}

		reconstructedPrivateKey, err := shamirDealer.Open(shamirShares...)
		require.NoError(t, err)
		require.Equal(t, expectedChildSecretKeyHex, hex.EncodeToString(reconstructedPrivateKey.Bytes()))

		derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
		aliceShard, exists := shards.Get(identities[0])
		require.True(t, exists)
		require.True(t, aliceShard.Shard.SigningKeyShare.PublicKey.Equal(derivedPublicKey))
	})

	t.Run("all encrypted shares decrypts to correct values", func(t *testing.T) {
		t.Parallel()

		for myIdentityKey, myShard := range shards.Iter() {
			myShare := myShard.Shard.SigningKeyShare.Share
			myPaillierPrivateKey := myShard.Shard.PaillierSecretKey
			mySharingId, exists := sharingConfig.Reverse().Get(myIdentityKey)
			require.True(t, exists)
			for _, value := range shards.Iter() {
				theirShard := value
				if myShard.Shard.PaillierSecretKey.N.Nat().Eq(theirShard.Shard.PaillierSecretKey.N.Nat()) == 0 {
					theirEncryptedShare, exists := theirShard.Shard.PaillierEncryptedShares.Get(mySharingId)
					require.True(t, exists)
					theirDecryptedShareInt, err := myPaillierPrivateKey.Decrypt(theirEncryptedShare)
					require.NoError(t, err)
					theirDecryptedShare, err := curve.ScalarField().Element().SetBytesWide(theirDecryptedShareInt.Abs().Big().Bytes())
					require.NoError(t, err)
					require.NotZero(t, theirDecryptedShare.Equal(myShare))
				}
			}
		}
	})
}

func Test_Regression(t *testing.T) {
	// If this test fails, it means the way chain code is computed had changed.
	// This would be a breaking change rendering existing HD addresses unusable, leading potentially to loss of funds.
	// This test is here to ensure that the change is intentional and not a bug.
	t.Parallel()

	data := "[{\"SigningKeyShare\":{\"Share\":{\"type\":\"secp256k1\",\"bytes\":\"q1PDDx7GHImCog4zGrOneUEZiK3rsGlAuAm6gPE/oBQ=\"},\"PublicKey\":{\"type\":\"secp256k1\",\"bytes\":\"AgDFNHNxDq5FFxh9O4lfyzDOqJR3MOTfqKHhC8y4YG03\"}},\"PublicKeyShares\":{\"PublicKey\":{\"type\":\"secp256k1\",\"bytes\":\"AgDFNHNxDq5FFxh9O4lfyzDOqJR3MOTfqKHhC8y4YG03\"},\"Shares\":{\"1\":{\"type\":\"secp256k1\",\"bytes\":\"AuWpyRm/RdQ6z4KibhIancyyX2eIuZ6REmsyyF8/huIg\"},\"2\":{\"type\":\"secp256k1\",\"bytes\":\"A/hP5LwGL+gBEnAVy8E93kD+wUE1pCVWU6EYw1rCenlg\"},\"3\":{\"type\":\"secp256k1\",\"bytes\":\"AnVkaTHENlhwYfFB2l4/yOSxYpQc9Y9L3N6kQlQXFbqV\"}},\"FeldmanCommitmentVector\":[{\"type\":\"secp256k1\",\"bytes\":\"AgDFNHNxDq5FFxh9O4lfyzDOqJR3MOTfqKHhC8y4YG03\"},{\"type\":\"secp256k1\",\"bytes\":\"A+Q6KZvueUWhcohQkhIyjLRDCY212Z1GEW3tR6ok5Qd4\"}]},\"PaillierSecretKey\":{\"p\":\"de57d3001ba222296125efb5edc4e914032397042c1aecc966d1f53159bab56a53f3e1f7c69005fb187c35cacd0deaf2b7ca7edb4317e05096b447b30a580809\",\"q\":\"e8b30b7a3dc561b092ea55d0df4ec37c143b700bc1d40fde6c7cfe2c08ee59f80c9e93d4372148ce2afe644b3c9c13fc453d1db391c2cc0b34c301f7122c79b9\"},\"PaillierPublicKeys\":{\"1\":{\"n\":\"b8b349957ab36eda1400c30142075d53d597132fe6cca50d913df163814bbc65fd286f553095d4fac13c2c0c06488ac10216e9a1f711167baf5b2091d0530160608d883d6afaefe56d8710093eb3d8f12fcec8ea518a07a22eba497a539522c56b05ab2fb4751a3921363f5b94919685b98e6a5f1dafd5f2e226f37075f87b3f\"},\"2\":{\"n\":\"99481f913b3647c831de69378be64d5158267ffa31f78de151e6059f3d9d38e40494f64cf885a2b3ccc09a584e1e1385030a06a949f9be9151f755b39cf4ef7919f2c504723c46a42d0f497632f2735dff419814aa0690eb0759a008de32d806da86fda5a64eaaca520f1d79331e51791486cefd231c7790f0e2d70b3614dd01\"}},\"PaillierEncryptedShares\":{\"1\":\"447d883efbde158659d29b22e8abe5afef62cd7e50ce9b680f36b3e16a7a292790544464fd687e230a8246eecafed3461fee5f6fcf5f5d97751db2a1b7cd682d7a59b795f6e5401a28a94f7072037cc5aa61331cc0f5f545ab7ff003c4190bff3d0fe19926fa58fbd0d0af58d47949ea2486b6cdbedb2f44d2c7c0f19b5141ca212cda9ff8d6861509f773464df46816f674d305414d9f196f14d3eac8f4e6c54cfa13eddb011681473bf0da533bef6820dcdaa758ec552b3fc1f5465155e12ddb9b217c079a26b73432b0faec146be132c1f129d6a1567941f7d8f4d6b51d3dcb69571e6f9a8419e9ed97d8768bac2187a0a7cfbb9ccf10ef9b9418b0cf19a7\",\"2\":\"12700fb69067ecb4347d5e3793922cca16cb8bb2dcbe59ddbe41e0b03c32dd28a3a926de76be8e1a690443aeb684a6b552b858eb6d2acf7d492eeecf44a993b420efba274e75561a8e5086e3cb79c1bb049292d86b7202e3746933f6278915f4a8b9f0a4495d5811ac15b4da04014fe0e00f44464304fbf50ec4821dc9adc200a1e45be0564f710632cc16503a3ae8da918b35081b6e732e197a572ca6f57b8a618330e4677564344c73e0fd7f068b6f49e6010c75e3b26fe2fdb888b2a0e911fe92e1273093d556d7cfae3510fa802a2e0fdabb39faac567de08045432725971c60aa4664d395b0a7c45920e6545d5f37fb82f7a98248e7885d4ca9dccd2e59\"}},{\"SigningKeyShare\":{\"Share\":{\"type\":\"secp256k1\",\"bytes\":\"3rb9e6s1sLeXeiHMi+BaAm5gxylxCc/3F6f4JjvDYWw=\"},\"PublicKey\":{\"type\":\"secp256k1\",\"bytes\":\"AgDFNHNxDq5FFxh9O4lfyzDOqJR3MOTfqKHhC8y4YG03\"}},\"PublicKeyShares\":{\"PublicKey\":{\"type\":\"secp256k1\",\"bytes\":\"AgDFNHNxDq5FFxh9O4lfyzDOqJR3MOTfqKHhC8y4YG03\"},\"Shares\":{\"1\":{\"type\":\"secp256k1\",\"bytes\":\"AuWpyRm/RdQ6z4KibhIancyyX2eIuZ6REmsyyF8/huIg\"},\"2\":{\"type\":\"secp256k1\",\"bytes\":\"A/hP5LwGL+gBEnAVy8E93kD+wUE1pCVWU6EYw1rCenlg\"},\"3\":{\"type\":\"secp256k1\",\"bytes\":\"AnVkaTHENlhwYfFB2l4/yOSxYpQc9Y9L3N6kQlQXFbqV\"}},\"FeldmanCommitmentVector\":[{\"type\":\"secp256k1\",\"bytes\":\"AgDFNHNxDq5FFxh9O4lfyzDOqJR3MOTfqKHhC8y4YG03\"},{\"type\":\"secp256k1\",\"bytes\":\"A+Q6KZvueUWhcohQkhIyjLRDCY212Z1GEW3tR6ok5Qd4\"}]},\"PaillierSecretKey\":{\"p\":\"dfe3756cf61c599d9f210a048bdfeef8ea184ccb2328a43862817eec6742e6463b9d0e6ee9ebb2ed0f8ae0c384aec4890a24a70c3168dbb5b61bbd88c83284c9\",\"q\":\"d330f3b8f1cdc5e002e0b533a4eccc9a1aefb124eaf407aba96eef102654a6b5911b1de7a813882f4ef6895f9a80bcc9a319de5c99ae2a0db09922532d79abc7\"},\"PaillierPublicKeys\":{\"2\":{\"n\":\"99481f913b3647c831de69378be64d5158267ffa31f78de151e6059f3d9d38e40494f64cf885a2b3ccc09a584e1e1385030a06a949f9be9151f755b39cf4ef7919f2c504723c46a42d0f497632f2735dff419814aa0690eb0759a008de32d806da86fda5a64eaaca520f1d79331e51791486cefd231c7790f0e2d70b3614dd01\"},\"3\":{\"n\":\"ca1b189893b02c458e4dfb417db0d4b004805d369ce42b6cfa1be9271ff11ed2924cf4c26c6a52adcf467200ac05c549548ef893632b092c381fcda1e5cfcf1dc17a94452bc1c1310519fd5c9fa65cb12c766f09eb7b3780a520ff8ae244decc838fb043431da1c9b3126836e6d5e7b53ca2c4c2dd6eed5b4d7e31a718f60f81\"}},\"PaillierEncryptedShares\":{\"2\":\"4df6e16140dcb58751a9e5fb4082e033a82e394c9d8d9cfce8c7f8996026c445a4b706949092802cd31f408a9345ed11bec6b570aa9739b6943ad0f6d0e69206766aa8cf2030c67b1f5f38db182ea061e545472ab0d75e4617fd490cdccf58753c86e3383bc829c6557b6321a7263b4c51dc175550d07aab6306afd81ab203a91d1dec25d61c7fa7cde81265106f6b7ea4936c4496466333330010c090e46ffeb0426a164e8c32e27702e70b57a6f77b5a9e15476934ebf8816d55353f36f3e7a8d43bcf9a199d93261a2ff26cadcfc0a04b929a945393a7b0984069aed812d1cdd8c95e01dbc0c018db5de7eb4e84543e3f5885d8f30185d71f22856f67049c\",\"3\":\"466be4a57fc97f381dc2b31bb933453a6b789cae06d3471ed555dc5fb343fde35af9db86c9afa8334905813a2d78e9e31b273963148f0e1c22caeec29248adae7b640ec80ebdb915d3e5d0b6a3e9ac9328377e0fe20700aff8eace5f2352ad26c07f5aeb36579effd150693c534d71dd650f5b30eb3675a531370a0c978f23100edf93e660ccb5ffa301c149eb2e3f5a213583b32bb62145069d86543afa1d25cbd4830ed89065c0bb96a43c21f40fe17dace909e36e3468c50d037adf3ac93241cf914addcf13c1bcb5e606d27e10bc842513eb907eaad326e15eeaf92a30d22e601817640c204141d3a2275b72d24c71de900c61c9fe4778e7a2de4a005821\"}},{\"SigningKeyShare\":{\"Share\":{\"type\":\"secp256k1\",\"bytes\":\"xQVgRWT95qCNDhf/00oAvde9J+uuXRyb59jZU5aBgMA=\"},\"PublicKey\":{\"type\":\"secp256k1\",\"bytes\":\"AgDFNHNxDq5FFxh9O4lfyzDOqJR3MOTfqKHhC8y4YG03\"}},\"PublicKeyShares\":{\"PublicKey\":{\"type\":\"secp256k1\",\"bytes\":\"AgDFNHNxDq5FFxh9O4lfyzDOqJR3MOTfqKHhC8y4YG03\"},\"Shares\":{\"1\":{\"type\":\"secp256k1\",\"bytes\":\"AuWpyRm/RdQ6z4KibhIancyyX2eIuZ6REmsyyF8/huIg\"},\"2\":{\"type\":\"secp256k1\",\"bytes\":\"A/hP5LwGL+gBEnAVy8E93kD+wUE1pCVWU6EYw1rCenlg\"},\"3\":{\"type\":\"secp256k1\",\"bytes\":\"AnVkaTHENlhwYfFB2l4/yOSxYpQc9Y9L3N6kQlQXFbqV\"}},\"FeldmanCommitmentVector\":[{\"type\":\"secp256k1\",\"bytes\":\"AgDFNHNxDq5FFxh9O4lfyzDOqJR3MOTfqKHhC8y4YG03\"},{\"type\":\"secp256k1\",\"bytes\":\"A+Q6KZvueUWhcohQkhIyjLRDCY212Z1GEW3tR6ok5Qd4\"}]},\"PaillierSecretKey\":{\"p\":\"c303349a98f3f83de9a541f9af8ac1a80e934e6dc3972b2fc60f4ea0abecdbd8892a352b40d02af11b4e0ac3166d930c6694064141802a93f30b93ddd6dbdb97\",\"q\":\"c937ee5ca2949ba326da4fb809dfd5b2881c6c1b321148c8710ac19e8d9bc9396edf3302ddc00b8b7339de2c7225fc19753116c8d64e888bf7e1e05c935dff27\"},\"PaillierPublicKeys\":{\"1\":{\"n\":\"b8b349957ab36eda1400c30142075d53d597132fe6cca50d913df163814bbc65fd286f553095d4fac13c2c0c06488ac10216e9a1f711167baf5b2091d0530160608d883d6afaefe56d8710093eb3d8f12fcec8ea518a07a22eba497a539522c56b05ab2fb4751a3921363f5b94919685b98e6a5f1dafd5f2e226f37075f87b3f\"},\"3\":{\"n\":\"ca1b189893b02c458e4dfb417db0d4b004805d369ce42b6cfa1be9271ff11ed2924cf4c26c6a52adcf467200ac05c549548ef893632b092c381fcda1e5cfcf1dc17a94452bc1c1310519fd5c9fa65cb12c766f09eb7b3780a520ff8ae244decc838fb043431da1c9b3126836e6d5e7b53ca2c4c2dd6eed5b4d7e31a718f60f81\"}},\"PaillierEncryptedShares\":{\"1\":\"7f682df09f60f20d705a8749a5f6461cbb4c4d43c4ee2b06f9adcae43b72af9b07ccca757a3307ed16fc0f89414b58feec666b53c1ef5f6b812f0fb5b84c88d9117904bbf621fe10b6cfa9d9c80228578b39cd547853c14ee827ec0a5d52ed841bfcc808db2070ce7f54cb277afb5501da4b31424c408008fde6dc396f52e14c85c7f7bde1a288af046391af7159e5c93d3f8a35d4b9e086d5e79e9b4dffdcb8e2669663e412a8812349ad70c5cf940baf0ba4c084a733a00f5263c135be2af0fa5d4aa1151839e1154a1f836ce22f2cab999d77d54ef18055a6adc1e5e3ed71b69a7d2dad67e359f99100f2b549c1584c198bd3ff5c73d6f4202492c514effc\",\"3\":\"0a2789ccd72775a7347cae07ac25e6d8249cb5e5d0bf18d8a4d13a316ce20503037be0033fc822095a55fa15fd198ff83018a96a52909ad0d1b0d0e15a10c422b6643c7731ea4f4cdd05be16f1712cdfb86388c6d79b9d2b1ab441d40ee99a76851f1628c7044d46b435c24cd47246d6a043b9b062c0562782695d7ee64d7ddac58d749884fe041e63e8d733b04ed2a6b38ca0b52288457d19cf55d677d8c493067bc99c9ccb24baf52561737dd4a089e030cd3356c349cbbfe7a14a27b85ef463dc0eabd3bab5c31507edb2eef0bcfe7c290053b21c0799b756f6b289826e8c86bfeea2b5dbb3c41e348899c6d276a3c801a6ce0361fc4f71aa5a9f3a3844e6\"}}]"
	var shards []*lindell17.Shard
	err := json.Unmarshal([]byte(data), &shards)
	require.NoError(t, err)

	require.Equal(t, "9309997c9d6f642912196cff94a53490a805644ac1572650bb3bed3c131c4f39", hex.EncodeToString(shards[0].ChainCode()))
	require.Equal(t, "9309997c9d6f642912196cff94a53490a805644ac1572650bb3bed3c131c4f39", hex.EncodeToString(shards[1].ChainCode()))
	require.Equal(t, "9309997c9d6f642912196cff94a53490a805644ac1572650bb3bed3c131c4f39", hex.EncodeToString(shards[2].ChainCode()))
}
