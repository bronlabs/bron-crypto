package hpke

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func dehex(h string) []byte {
	result, _ := hex.DecodeString(h)
	return result
}

type setupInfo struct {
	mode   ModeID
	kemId  KEMID
	kdfId  KDFID
	aeadId AEADID

	info                 []byte
	ikmE                 []byte
	pkEm                 []byte
	skEm                 []byte
	ikmR                 []byte
	pkRm                 []byte
	skRm                 []byte
	enc                  []byte
	shared_secret        []byte
	key_schedule_context []byte
	secret               []byte
	key                  []byte
	base_nonce           []byte
	exporter_secret      []byte

	psk    []byte
	psk_id []byte

	ikmS []byte
	pkSm []byte
	skSm []byte
}

type encryptionInfo struct {
	seq   uint64
	pt    []byte
	aad   []byte
	nonce []byte
	ct    []byte
}

type exportInfo struct {
	exporter_context []byte
	L                int
	exported_value   []byte
}

type authSuite struct {
	mode        ModeID
	setup       *setupInfo
	encryptions []*encryptionInfo
	exports     []*exportInfo
}

type suite struct {
	name  string
	auths []*authSuite
}

var tests = []*suite{
	{
		name: "DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM",
		auths: []*authSuite{
			// https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.3.1
			{
				mode: Base,
				setup: &setupInfo{
					mode:                 Base,
					kemId:                DHKEM_P256_HKDF_SHA256,
					kdfId:                KDF_HKDF_SHA256,
					aeadId:               AEAD_AES_128_GCM,
					info:                 dehex("4f6465206f6e2061204772656369616e2055726e"),
					ikmE:                 dehex("4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e"),
					pkEm:                 dehex("04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4"),
					skEm:                 dehex("4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb"),
					ikmR:                 dehex("668b37171f1072f3cf12ea8a236a45df23fc13b82af3609ad1e354f6ef817550"),
					pkRm:                 dehex("04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0"),
					skRm:                 dehex("f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2"),
					enc:                  dehex("04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4"),
					shared_secret:        dehex("c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8"),
					key_schedule_context: dehex("00b88d4e6d91759e65e87c470e8b9141113e9ad5f0c8ceefc1e088c82e6980500798e486f9c9c09c9b5c753ac72d6005de254c607d1b534ed11d493ae1c1d9ac85"),
					secret:               dehex("2eb7b6bf138f6b5aff857414a058a3f1750054a9ba1f72c2cf0684a6f20b10e1"),
					key:                  dehex("868c066ef58aae6dc589b6cfdd18f97e"),
					base_nonce:           dehex("4e0bc5018beba4bf004cca59"),
					exporter_secret:      dehex("14ad94af484a7ad3ef40e9f3be99ecc6fa9036df9d4920548424df127ee0d99f"),
				},
				encryptions: []*encryptionInfo{
					{
						seq:   0,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d30"),
						nonce: dehex("4e0bc5018beba4bf004cca59"),
						ct:    dehex("5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434"),
					},
					{
						seq:   1,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d31"),
						nonce: dehex("4e0bc5018beba4bf004cca58"),
						ct:    dehex("fa6f037b47fc21826b610172ca9637e82d6e5801eb31cbd3748271affd4ecb06646e0329cbdf3c3cd655b28e82"),
					},
					{
						seq:   2,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d32"),
						nonce: dehex("4e0bc5018beba4bf004cca5b"),
						ct:    dehex("895cabfac50ce6c6eb02ffe6c048bf53b7f7be9a91fc559402cbc5b8dcaeb52b2ccc93e466c28fb55fed7a7fec"),
					},
					{
						seq:   4,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d34"),
						nonce: dehex("4e0bc5018beba4bf004cca5d"),
						ct:    dehex("8787491ee8df99bc99a246c4b3216d3d57ab5076e18fa27133f520703bc70ec999dd36ce042e44f0c3169a6a8f"),
					},
					{
						seq:   255,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d323535"),
						nonce: dehex("4e0bc5018beba4bf004ccaa6"),
						ct:    dehex("2ad71c85bf3f45c6eca301426289854b31448bcf8a8ccb1deef3ebd87f60848aa53c538c30a4dac71d619ee2cd"),
					},
					{
						seq:   256,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d323536"),
						nonce: dehex("4e0bc5018beba4bf004ccb59"),
						ct:    dehex("10f179686aa2caec1758c8e554513f16472bd0a11e2a907dde0b212cbe87d74f367f8ffe5e41cd3e9962a6afb2"),
					},
				},
				exports: []*exportInfo{
					{
						exporter_context: nil,
						L:                32,
						exported_value:   dehex("5e9bc3d236e1911d95e65b576a8a86d478fb827e8bdfe77b741b289890490d4d"),
					},
					{
						exporter_context: dehex("00"),
						L:                32,
						exported_value:   dehex("6cff87658931bda83dc857e6353efe4987a201b849658d9b047aab4cf216e796"),
					},
					{
						exporter_context: dehex("54657374436f6e74657874"),
						L:                32,
						exported_value:   dehex("d8f1ea7942adbba7412c6d431c62d01371ea476b823eb697e1f6e6cae1dab85a"),
					},
				},
			},

			// https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.3.2
			{
				mode: PSk,
				setup: &setupInfo{
					mode: PSk,

					kdfId:  KDF_HKDF_SHA256,
					kemId:  DHKEM_P256_HKDF_SHA256,
					aeadId: AEAD_AES_128_GCM,

					info:                 dehex("4f6465206f6e2061204772656369616e2055726e"),
					ikmE:                 dehex("2afa611d8b1a7b321c761b483b6a053579afa4f767450d3ad0f84a39fda587a6"),
					pkEm:                 dehex("04305d35563527bce037773d79a13deabed0e8e7cde61eecee403496959e89e4d0ca701726696d1485137ccb5341b3c1c7aaee90a4a02449725e744b1193b53b5f"),
					skEm:                 dehex("57427244f6cc016cddf1c19c8973b4060aa13579b4c067fd5d93a5d74e32a90f"),
					ikmR:                 dehex("d42ef874c1913d9568c9405407c805baddaffd0898a00f1e84e154fa787b2429"),
					pkRm:                 dehex("040d97419ae99f13007a93996648b2674e5260a8ebd2b822e84899cd52d87446ea394ca76223b76639eccdf00e1967db10ade37db4e7db476261fcc8df97c5ffd1"),
					skRm:                 dehex("438d8bcef33b89e0e9ae5eb0957c353c25a94584b0dd59c991372a75b43cb661"),
					psk:                  dehex("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82"),
					psk_id:               dehex("456e6e796e20447572696e206172616e204d6f726961"),
					enc:                  dehex("04305d35563527bce037773d79a13deabed0e8e7cde61eecee403496959e89e4d0ca701726696d1485137ccb5341b3c1c7aaee90a4a02449725e744b1193b53b5f"),
					shared_secret:        dehex("2e783ad86a1beae03b5749e0f3f5e9bb19cb7eb382f2fb2dd64c99f15ae0661b"),
					key_schedule_context: dehex("01b873cdf2dff4c1434988053b7a775e980dd2039ea24f950b26b056ccedcb933198e486f9c9c09c9b5c753ac72d6005de254c607d1b534ed11d493ae1c1d9ac85"),
					secret:               dehex("f2f534e55931c62eeb2188c1f53450354a725183937e68c85e68d6b267504d26"),
					key:                  dehex("55d9eb9d26911d4c514a990fa8d57048"),
					base_nonce:           dehex("b595dc6b2d7e2ed23af529b1"),
					exporter_secret:      dehex("895a723a1eab809804973a53c0ee18ece29b25a7555a4808277ad2651d66d705"),
				},
				encryptions: []*encryptionInfo{
					{
						seq:   0,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d30"),
						nonce: dehex("b595dc6b2d7e2ed23af529b1"),
						ct:    dehex("90c4deb5b75318530194e4bb62f890b019b1397bbf9d0d6eb918890e1fb2be1ac2603193b60a49c2126b75d0eb"),
					},
					{
						seq:   1,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d31"),
						nonce: dehex("b595dc6b2d7e2ed23af529b0"),
						ct:    dehex("9e223384a3620f4a75b5a52f546b7262d8826dea18db5a365feb8b997180b22d72dc1287f7089a1073a7102c27"),
					},
					{
						seq:   2,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d32"),
						nonce: dehex("b595dc6b2d7e2ed23af529b3"),
						ct:    dehex("adf9f6000773035023be7d415e13f84c1cb32a24339a32eb81df02be9ddc6abc880dd81cceb7c1d0c7781465b2"),
					},
					{
						seq:   4,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d34"),
						nonce: dehex("b595dc6b2d7e2ed23af529b5"),
						ct:    dehex("1f4cc9b7013d65511b1f69c050b7bd8bbd5a5c16ece82b238fec4f30ba2400e7ca8ee482ac5253cffb5c3dc577"),
					},
					{
						seq:   255,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d323535"),
						nonce: dehex("b595dc6b2d7e2ed23af5294e"),
						ct:    dehex("cdc541253111ed7a424eea5134dc14fc5e8293ab3b537668b8656789628e45894e5bb873c968e3b7cdcbb654a4"),
					},
					{
						seq:   256,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d323536"),
						nonce: dehex("b595dc6b2d7e2ed23af528b1"),
						ct:    dehex("faf985208858b1253b97b60aecd28bc18737b58d1242370e7703ec33b73a4c31a1afee300e349adef9015bbbfd"),
					},
				},
				exports: []*exportInfo{
					{
						exporter_context: nil,
						L:                32,
						exported_value:   dehex("a115a59bf4dd8dc49332d6a0093af8efca1bcbfd3627d850173f5c4a55d0c185"),
					},
					{
						exporter_context: dehex("00"),
						L:                32,
						exported_value:   dehex("4517eaede0669b16aac7c92d5762dd459c301fa10e02237cd5aeb9be969430c4"),
					},
					{
						exporter_context: dehex("54657374436f6e74657874"),
						L:                32,
						exported_value:   dehex("164e02144d44b607a7722e58b0f4156e67c0c2874d74cf71da6ca48a4cbdc5e0"),
					},
				},
			},

			// https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.3.3
			{
				mode: Auth,
				setup: &setupInfo{
					mode: Auth,

					kdfId:  KDF_HKDF_SHA256,
					kemId:  DHKEM_P256_HKDF_SHA256,
					aeadId: AEAD_AES_128_GCM,

					info:                 dehex("4f6465206f6e2061204772656369616e2055726e"),
					ikmE:                 dehex("798d82a8d9ea19dbc7f2c6dfa54e8a6706f7cdc119db0813dacf8440ab37c857"),
					pkEm:                 dehex("042224f3ea800f7ec55c03f29fc9865f6ee27004f818fcbdc6dc68932c1e52e15b79e264a98f2c535ef06745f3d308624414153b22c7332bc1e691cb4af4d53454"),
					skEm:                 dehex("6b8de0873aed0c1b2d09b8c7ed54cbf24fdf1dfc7a47fa501f918810642d7b91"),
					ikmR:                 dehex("7bc93bde8890d1fb55220e7f3b0c107ae7e6eda35ca4040bb6651284bf0747ee"),
					pkRm:                 dehex("04423e363e1cd54ce7b7573110ac121399acbc9ed815fae03b72ffbd4c18b01836835c5a09513f28fc971b7266cfde2e96afe84bb0f266920e82c4f53b36e1a78d"),
					skRm:                 dehex("d929ab4be2e59f6954d6bedd93e638f02d4046cef21115b00cdda2acb2a4440e"),
					ikmS:                 dehex("874baa0dcf93595a24a45a7f042e0d22d368747daaa7e19f80a802af19204ba8"),
					pkSm:                 dehex("04a817a0902bf28e036d66add5d544cc3a0457eab150f104285df1e293b5c10eef8651213e43d9cd9086c80b309df22cf37609f58c1127f7607e85f210b2804f73"),
					skSm:                 dehex("1120ac99fb1fccc1e8230502d245719d1b217fe20505c7648795139d177f0de9"),
					enc:                  dehex("042224f3ea800f7ec55c03f29fc9865f6ee27004f818fcbdc6dc68932c1e52e15b79e264a98f2c535ef06745f3d308624414153b22c7332bc1e691cb4af4d53454"),
					shared_secret:        dehex("d4aea336439aadf68f9348880aa358086f1480e7c167b6ef15453ba69b94b44f"),
					key_schedule_context: dehex("02b88d4e6d91759e65e87c470e8b9141113e9ad5f0c8ceefc1e088c82e6980500798e486f9c9c09c9b5c753ac72d6005de254c607d1b534ed11d493ae1c1d9ac85"),
					secret:               dehex("fd0a93c7c6f6b1b0dd6a822d7b16f6c61c83d98ad88426df4613c3581a2319f1"),
					key:                  dehex("19aa8472b3fdc530392b0e54ca17c0f5"),
					base_nonce:           dehex("b390052d26b67a5b8a8fcaa4"),
					exporter_secret:      dehex("f152759972660eb0e1db880835abd5de1c39c8e9cd269f6f082ed80e28acb164"),
				},
				encryptions: []*encryptionInfo{
					{
						seq:   0,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d30"),
						nonce: dehex("b390052d26b67a5b8a8fcaa4"),
						ct:    dehex("82ffc8c44760db691a07c5627e5fc2c08e7a86979ee79b494a17cc3405446ac2bdb8f265db4a099ed3289ffe19"),
					},
					{
						seq:   1,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d31"),
						nonce: dehex("b390052d26b67a5b8a8fcaa5"),
						ct:    dehex("b0a705a54532c7b4f5907de51c13dffe1e08d55ee9ba59686114b05945494d96725b239468f1229e3966aa1250"),
					},
					{
						seq:   2,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d32"),
						nonce: dehex("b390052d26b67a5b8a8fcaa6"),
						ct:    dehex("8dc805680e3271a801790833ed74473710157645584f06d1b53ad439078d880b23e25256663178271c80ee8b7c"),
					},
					{
						seq:   4,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d34"),
						nonce: dehex("b390052d26b67a5b8a8fcaa0"),
						ct:    dehex("04c8f7aae1584b61aa5816382cb0b834a5d744f420e6dffb5ddcec633a21b8b3472820930c1ea9258b035937a2"),
					},
					{
						seq:   255,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d323535"),
						nonce: dehex("b390052d26b67a5b8a8fca5b"),
						ct:    dehex("4a319462eaedee37248b4d985f64f4f863d31913fe9e30b6e13136053b69fe5d70853c84c60a84bb5495d5a678"),
					},
					{
						seq:   256,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d323536"),
						nonce: dehex("b390052d26b67a5b8a8fcba4"),
						ct:    dehex("28e874512f8940fafc7d06135e7589f6b4198bc0f3a1c64702e72c9e6abaf9f05cb0d2f11b03a517898815c934"),
					},
				},
				exports: []*exportInfo{
					{
						exporter_context: nil,
						L:                32,
						exported_value:   dehex("837e49c3ff629250c8d80d3c3fb957725ed481e59e2feb57afd9fe9a8c7c4497"),
					},
					{
						exporter_context: dehex("00"),
						L:                32,
						exported_value:   dehex("594213f9018d614b82007a7021c3135bda7b380da4acd9ab27165c508640dbda"),
					},
					{
						exporter_context: dehex("54657374436f6e74657874"),
						L:                32,
						exported_value:   dehex("14fe634f95ca0d86e15247cca7de7ba9b73c9b9deb6437e1c832daf7291b79d5"),
					},
				},
			},

			// https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.3.4
			{
				mode: AuthPSk,
				setup: &setupInfo{
					mode: AuthPSk,

					kdfId:  KDF_HKDF_SHA256,
					kemId:  DHKEM_P256_HKDF_SHA256,
					aeadId: AEAD_AES_128_GCM,

					info:                 dehex("4f6465206f6e2061204772656369616e2055726e"),
					ikmE:                 dehex("3c1fceb477ec954c8d58ef3249e4bb4c38241b5925b95f7486e4d9f1d0d35fbb"),
					pkEm:                 dehex("046a1de3fc26a3d43f4e4ba97dbe24f7e99181136129c48fbe872d4743e2b131357ed4f29a7b317dc22509c7b00991ae990bf65f8b236700c82ab7c11a84511401"),
					skEm:                 dehex("36f771e411cf9cf72f0701ef2b991ce9743645b472e835fe234fb4d6eb2ff5a0"),
					ikmR:                 dehex("abcc2da5b3fa81d8aabd91f7f800a8ccf60ec37b1b585a5d1d1ac77f258b6cca"),
					pkRm:                 dehex("04d824d7e897897c172ac8a9e862e4bd820133b8d090a9b188b8233a64dfbc5f725aa0aa52c8462ab7c9188f1c4872f0c99087a867e8a773a13df48a627058e1b3"),
					skRm:                 dehex("bdf4e2e587afdf0930644a0c45053889ebcadeca662d7c755a353d5b4e2a8394"),
					ikmS:                 dehex("6262031f040a9db853edd6f91d2272596eabbc78a2ed2bd643f770ecd0f19b82"),
					pkSm:                 dehex("049f158c750e55d8d5ad13ede66cf6e79801634b7acadcad72044eac2ae1d0480069133d6488bf73863fa988c4ba8bde1c2e948b761274802b4d8012af4f13af9e"),
					skSm:                 dehex("b0ed8721db6185435898650f7a677affce925aba7975a582653c4cb13c72d240"),
					psk:                  dehex("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82"),
					psk_id:               dehex("456e6e796e20447572696e206172616e204d6f726961"),
					enc:                  dehex("046a1de3fc26a3d43f4e4ba97dbe24f7e99181136129c48fbe872d4743e2b131357ed4f29a7b317dc22509c7b00991ae990bf65f8b236700c82ab7c11a84511401"),
					shared_secret:        dehex("d4c27698391db126f1612d9e91a767f10b9b19aa17e1695549203f0df7d9aebe"),
					key_schedule_context: dehex("03b873cdf2dff4c1434988053b7a775e980dd2039ea24f950b26b056ccedcb933198e486f9c9c09c9b5c753ac72d6005de254c607d1b534ed11d493ae1c1d9ac85"),
					secret:               dehex("3bf9d4c7955da2740414e73081fa74d6f6f2b4b9645d0685219813ce99a2f270"),
					key:                  dehex("4d567121d67fae1227d90e11585988fb"),
					base_nonce:           dehex("67c9d05330ca21e5116ecda6"),
					exporter_secret:      dehex("3f479020ae186788e4dfd4a42a21d24f3faabb224dd4f91c2b2e5e9524ca27b2"),
				},
				encryptions: []*encryptionInfo{
					{
						seq:   0,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d30"),
						nonce: dehex("67c9d05330ca21e5116ecda6"),
						ct:    dehex("b9f36d58d9eb101629a3e5a7b63d2ee4af42b3644209ab37e0a272d44365407db8e655c72e4fa46f4ff81b9246"),
					},
					{
						seq:   1,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d31"),
						nonce: dehex("67c9d05330ca21e5116ecda7"),
						ct:    dehex("51788c4e5d56276771032749d015d3eea651af0c7bb8e3da669effffed299ea1f641df621af65579c10fc09736"),
					},
					{
						seq:   2,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d32"),
						nonce: dehex("67c9d05330ca21e5116ecda4"),
						ct:    dehex("3b5a2be002e7b29927f06442947e1cf709b9f8508b03823127387223d712703471c266efc355f1bc2036f3027c"),
					},
					{
						seq:   4,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d34"),
						nonce: dehex("67c9d05330ca21e5116ecda2"),
						ct:    dehex("8ddbf1242fe5c7d61e1675496f3bfdb4d90205b3dfbc1b12aab41395d71a82118e095c484103107cf4face5123"),
					},
					{
						seq:   255,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d323535"),
						nonce: dehex("67c9d05330ca21e5116ecd59"),
						ct:    dehex("6de25ceadeaec572fbaa25eda2558b73c383fe55106abaec24d518ef6724a7ce698f83ecdc53e640fe214d2f42"),
					},
					{
						seq:   256,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d323536"),
						nonce: dehex("67c9d05330ca21e5116ecca6"),
						ct:    dehex("f380e19d291e12c5e378b51feb5cd50f6d00df6cb2af8393794c4df342126c2e29633fe7e8ce49587531affd4d"),
					},
				},
				exports: []*exportInfo{
					{
						exporter_context: nil,
						L:                32,
						exported_value:   dehex("595ce0eff405d4b3bb1d08308d70a4e77226ce11766e0a94c4fdb5d90025c978"),
					},
					{
						exporter_context: dehex("00"),
						L:                32,
						exported_value:   dehex("110472ee0ae328f57ef7332a9886a1992d2c45b9b8d5abc9424ff68630f7d38d"),
					},
					{
						exporter_context: dehex("54657374436f6e74657874"),
						L:                32,
						exported_value:   dehex("18ee4d001a9d83a4c67e76f88dd747766576cac438723bad0700a910a4d717e6"),
					},
				},
			},
		},
	},
	{
		name: "DHKEM(P-256, HKDF-SHA256), HKDF-SHA512, AES-128-GCM",
		auths: []*authSuite{
			// https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.4.1
			{
				mode: Base,
				setup: &setupInfo{
					mode:                 Base,
					kemId:                DHKEM_P256_HKDF_SHA256,
					kdfId:                KDF_HKDF_SHA512,
					aeadId:               AEAD_AES_128_GCM,
					info:                 dehex("4f6465206f6e2061204772656369616e2055726e"),
					ikmE:                 dehex("4ab11a9dd78c39668f7038f921ffc0993b368171d3ddde8031501ee1e08c4c9a"),
					pkEm:                 dehex("0493ed86735bdfb978cc055c98b45695ad7ce61ce748f4dd63c525a3b8d53a15565c6897888070070c1579db1f86aaa56deb8297e64db7e8924e72866f9a472580"),
					skEm:                 dehex("2292bf14bb6e15b8c81a0f45b7a6e93e32d830e48cca702e0affcfb4d07e1b5c"),
					ikmR:                 dehex("ea9ff7cc5b2705b188841c7ace169290ff312a9cb31467784ca92d7a2e6e1be8"),
					pkRm:                 dehex("04085aa5b665dc3826f9650ccbcc471be268c8ada866422f739e2d531d4a8818a9466bc6b449357096232919ec4fe9070ccbac4aac30f4a1a53efcf7af90610edd"),
					skRm:                 dehex("3ac8530ad1b01885960fab38cf3cdc4f7aef121eaa239f222623614b4079fb38"),
					enc:                  dehex("0493ed86735bdfb978cc055c98b45695ad7ce61ce748f4dd63c525a3b8d53a15565c6897888070070c1579db1f86aaa56deb8297e64db7e8924e72866f9a472580"),
					shared_secret:        dehex("02f584736390fc93f5b4ad039826a3fa08e9911bd1215a3db8e8791ba533cafd"),
					key_schedule_context: dehex("005b8a3617af7789ee716e7911c7e77f84cdc4cc46e60fb7e19e4059f9aeadc00585e26874d1ddde76e551a7679cd47168c466f6e1f705cc9374c192778a34fcd5ca221d77e229a9d11b654de7942d685069c633b2362ce3b3d8ea4891c9a2a87a4eb7cdb289ba5e2ecbf8cd2c8498bb4a383dc021454d70d46fcbbad1252ef4f9"),
					secret:               dehex("0c7acdab61693f936c4c1256c78e7be30eebfe466812f9cc49f0b58dc970328dfc03ea359be0250a471b1635a193d2dfa8cb23c90aa2e25025b892a725353eeb"),
					key:                  dehex("090ca96e5f8aa02b69fac360da50ddf9"),
					base_nonce:           dehex("9c995e621bf9a20c5ca45546"),
					exporter_secret:      dehex("4a7abb2ac43e6553f129b2c5750a7e82d149a76ed56dc342d7bca61e26d494f4855dff0d0165f27ce57756f7f16baca006539bb8e4518987ba610480ac03efa8"),
				},
				encryptions: []*encryptionInfo{
					{
						seq:   0,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d30"),
						nonce: dehex("9c995e621bf9a20c5ca45546"),
						ct:    dehex("d3cf4984931484a080f74c1bb2a6782700dc1fef9abe8442e44a6f09044c88907200b332003543754eb51917ba"),
					},
					{
						seq:   1,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d31"),
						nonce: dehex("9c995e621bf9a20c5ca45547"),
						ct:    dehex("d14414555a47269dfead9fbf26abb303365e40709a4ed16eaefe1f2070f1ddeb1bdd94d9e41186f124e0acc62d"),
					},
					{
						seq:   2,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d32"),
						nonce: dehex("9c995e621bf9a20c5ca45544"),
						ct:    dehex("9bba136cade5c4069707ba91a61932e2cbedda2d9c7bdc33515aa01dd0e0f7e9d3579bf4016dec37da4aafa800"),
					},
					{
						seq:   4,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d34"),
						nonce: dehex("9c995e621bf9a20c5ca45542"),
						ct:    dehex("a531c0655342be013bf32112951f8df1da643602f1866749519f5dcb09cc68432579de305a77e6864e862a7600"),
					},
					{
						seq:   255,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d323535"),
						nonce: dehex("9c995e621bf9a20c5ca455b9"),
						ct:    dehex("be5da649469efbad0fb950366a82a73fefeda5f652ec7d3731fac6c4ffa21a7004d2ab8a04e13621bd3629547d"),
					},
					{
						seq:   256,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d323536"),
						nonce: dehex("9c995e621bf9a20c5ca45446"),
						ct:    dehex("62092672f5328a0dde095e57435edf7457ace60b26ee44c9291110ec135cb0e14b85594e4fea11247d937deb62"),
					},
				},
				exports: []*exportInfo{
					{
						exporter_context: nil,
						L:                32,
						exported_value:   dehex("a32186b8946f61aeead1c093fe614945f85833b165b28c46bf271abf16b57208"),
					},
					{
						exporter_context: dehex("00"),
						L:                32,
						exported_value:   dehex("84998b304a0ea2f11809398755f0abd5f9d2c141d1822def79dd15c194803c2a"),
					},
					{
						exporter_context: dehex("54657374436f6e74657874"),
						L:                32,
						exported_value:   dehex("93fb9411430b2cfa2cf0bed448c46922a5be9beff20e2e621df7e4655852edbc"),
					},
				},
			},
			// https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.4.2
			{
				mode: PSk,
				setup: &setupInfo{
					mode:                 PSk,
					kemId:                DHKEM_P256_HKDF_SHA256,
					kdfId:                KDF_HKDF_SHA512,
					aeadId:               AEAD_AES_128_GCM,
					info:                 dehex("4f6465206f6e2061204772656369616e2055726e"),
					ikmE:                 dehex("c11d883d6587f911d2ddbc2a0859d5b42fb13bf2c8e89ef408a25564893856f5"),
					pkEm:                 dehex("04a307934180ad5287f95525fe5bc6244285d7273c15e061f0f2efb211c35057f3079f6e0abae200992610b25f48b63aacfcb669106ddee8aa023feed301901371"),
					skEm:                 dehex("a5901ff7d6931959c2755382ea40a4869b1dec3694ed3b009dda2d77dd488f18"),
					ikmR:                 dehex("75bfc2a3a3541170a54c0b06444e358d0ee2b4fb78a401fd399a47a33723b700"),
					pkRm:                 dehex("043f5266fba0742db649e1043102b8a5afd114465156719cea90373229aabdd84d7f45dabfc1f55664b888a7e86d594853a6cccdc9b189b57839cbbe3b90b55873"),
					skRm:                 dehex("bc6f0b5e22429e5ff47d5969003f3cae0f4fec50e23602e880038364f33b8522"),
					psk:                  dehex("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82"),
					psk_id:               dehex("456e6e796e20447572696e206172616e204d6f726961"),
					enc:                  dehex("04a307934180ad5287f95525fe5bc6244285d7273c15e061f0f2efb211c35057f3079f6e0abae200992610b25f48b63aacfcb669106ddee8aa023feed301901371"),
					shared_secret:        dehex("2912aacc6eaebd71ff715ea50f6ef3a6637856b2a4c58ea61e0c3fc159e3bc16"),
					key_schedule_context: dehex("01713f73042575cebfd132f0cc4338523f8eae95c80a749f7cf3eb9436ff1c612ca62c37df27ca46d2cc162445a92c5f5fdc57bcde129ca7b1f284b0c12297c037ca221d77e229a9d11b654de7942d685069c633b2362ce3b3d8ea4891c9a2a87a4eb7cdb289ba5e2ecbf8cd2c8498bb4a383dc021454d70d46fcbbad1252ef4f9"),
					secret:               dehex("ff2051d2128d5f3078de867143e076262ce1d0aecafc3fff3d607f1eaff05345c7d5ffcb3202cdecb3d1a2f7da20592a237747b6e855390cbe2109d3e6ac70c2"),
					key:                  dehex("0b910ba8d9cfa17e5f50c211cb32839a"),
					base_nonce:           dehex("0c29e714eb52de5b7415a1b7"),
					exporter_secret:      dehex("50c0a182b6f94b4c0bd955c4aa20df01f282cc12c43065a0812fe4d4352790171ed2b2c4756ad7f5a730ba336c8f1edd0089d8331192058c385bae39c7cc8b57"),
				},
				encryptions: []*encryptionInfo{
					{
						seq:   0,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d30"),
						nonce: dehex("0c29e714eb52de5b7415a1b7"),
						ct:    dehex("57624b6e320d4aba0afd11f548780772932f502e2ba2a8068676b2a0d3b5129a45b9faa88de39e8306da41d4cc"),
					},
					{
						seq:   1,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d31"),
						nonce: dehex("0c29e714eb52de5b7415a1b6"),
						ct:    dehex("159d6b4c24bacaf2f5049b7863536d8f3ffede76302dace42080820fa51925d4e1c72a64f87b14291a3057e00a"),
					},
					{
						seq:   2,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d32"),
						nonce: dehex("0c29e714eb52de5b7415a1b5"),
						ct:    dehex("bd24140859c99bf0055075e9c460032581dd1726d52cf980d308e9b20083ca62e700b17892bcf7fa82bac751d0"),
					},
					{
						seq:   4,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d34"),
						nonce: dehex("0c29e714eb52de5b7415a1b3"),
						ct:    dehex("93ddd55f82e9aaaa3cfc06840575f09d80160b20538125c2549932977d1238dde8126a4a91118faf8632f62cb8"),
					},
					{
						seq:   255,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d323535"),
						nonce: dehex("0c29e714eb52de5b7415a148"),
						ct:    dehex("377a98a3c34bf716581b05a6b3fdc257f245856384d5f2241c8840571c52f5c85c21138a4a81655edab8fe227d"),
					},
					{
						seq:   256,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d323536"),
						nonce: dehex("0c29e714eb52de5b7415a0b7"),
						ct:    dehex("cc161f5a179831d456d119d2f2c19a6817289c75d1c61cd37ac8a450acd9efba02e0ac00d128c17855931ff69a"),
					},
				},
				exports: []*exportInfo{
					{
						exporter_context: nil,
						L:                32,
						exported_value:   dehex("8158bea21a6700d37022bb7802866edca30ebf2078273757b656ef7fc2e428cf"),
					},
					{
						exporter_context: dehex("00"),
						L:                32,
						exported_value:   dehex("6a348ba6e0e72bb3ef22479214a139ef8dac57be34509a61087a12565473da8d"),
					},
					{
						exporter_context: dehex("54657374436f6e74657874"),
						L:                32,
						exported_value:   dehex("2f6d4f7a18ec48de1ef4469f596aada4afdf6d79b037ed3c07e0118f8723bffc"),
					},
				},
			},
			// https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.4.3
			{
				mode: Auth,
				setup: &setupInfo{
					mode:                 Auth,
					kemId:                DHKEM_P256_HKDF_SHA256,
					kdfId:                KDF_HKDF_SHA512,
					aeadId:               AEAD_AES_128_GCM,
					info:                 dehex("4f6465206f6e2061204772656369616e2055726e"),
					ikmE:                 dehex("6bb031aa9197562da0b44e737db2b9e61f6c3ea1138c37de28fc37ac29bc7350"),
					pkEm:                 dehex("04fec59fa9f76f5d0f6c1660bb179cb314ed97953c53a60ab38f8e6ace60fd59178084d0dd66e0f79172992d4ddb2e91172ce24949bcebfff158dcc417f2c6e9c6"),
					skEm:                 dehex("93cddd5288e7ef4884c8fe321d075df01501b993ff49ffab8184116f39b3c655"),
					ikmR:                 dehex("649a3f92edbb7a2516a0ade0b7dccc58a37240c4ba06f9726a952227b4adf6ff"),
					pkRm:                 dehex("04378bad519aab406e04d0e5608bcca809c02d6afd2272d4dd03e9357bd0eee8adf84c8deba3155c9cf9506d1d4c8bfefe3cf033a75716cc3cc07295100ec96276"),
					skRm:                 dehex("1ea4484be482bf25fdb2ed39e6a02ed9156b3e57dfb18dff82e4a048de990236"),
					ikmS:                 dehex("4d79b8691aab55a7265e8490a04bb3860ed64dece90953ad0dc43a6ea59b4bf2"),
					pkSm:                 dehex("0404d3c1f9fca22eb4a6d326125f0814c35593b1da8ea0d11a640730b215a259b9b98a34ad17e21617d19fe1d4fa39a4828bfdb306b729ec51c543caca3b2d9529"),
					skSm:                 dehex("02b266d66919f7b08f42ae0e7d97af4ca98b2dae3043bb7e0740ccadc1957579"),
					enc:                  dehex("04fec59fa9f76f5d0f6c1660bb179cb314ed97953c53a60ab38f8e6ace60fd59178084d0dd66e0f79172992d4ddb2e91172ce24949bcebfff158dcc417f2c6e9c6"),
					shared_secret:        dehex("1ed49f6d7ada333d171cd63861a1cb700a1ec4236755a9cd5f9f8f67a2f8e7b3"),
					key_schedule_context: dehex("025b8a3617af7789ee716e7911c7e77f84cdc4cc46e60fb7e19e4059f9aeadc00585e26874d1ddde76e551a7679cd47168c466f6e1f705cc9374c192778a34fcd5ca221d77e229a9d11b654de7942d685069c633b2362ce3b3d8ea4891c9a2a87a4eb7cdb289ba5e2ecbf8cd2c8498bb4a383dc021454d70d46fcbbad1252ef4f9"),
					secret:               dehex("9c846ba81ddbbd57bc26d99da6cf7ab956bb735ecd47fe21ed14241c70791b7484c1d06663d21a5d97bf1be70d56ab727f650c4f859c5ed3f71f8928b3c082dd"),
					key:                  dehex("9d4b1c83129f3de6db95faf3d539dcf1"),
					base_nonce:           dehex("ea4fd7a485ee5f1f4b62c1b7"),
					exporter_secret:      dehex("ca2410672369aae1afd6c2639f4fe34ca36d35410c090608d2924f60def17f910d7928575434d7f991b1f19d3e8358b8278ff59ced0d5eed4774cec72e12766e"),
				},
				encryptions: []*encryptionInfo{
					{
						seq:   0,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d30"),
						nonce: dehex("ea4fd7a485ee5f1f4b62c1b7"),
						ct:    dehex("2480179d880b5f458154b8bfe3c7e8732332de84aabf06fc440f6b31f169e154157fa9eb44f2fa4d7b38a9236e"),
					},
					{
						seq:   1,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d31"),
						nonce: dehex("ea4fd7a485ee5f1f4b62c1b6"),
						ct:    dehex("10cd81e3a816d29942b602a92884348171a31cbd0f042c3057c65cd93c540943a5b05115bd520c09281061935b"),
					},
					{
						seq:   2,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d32"),
						nonce: dehex("ea4fd7a485ee5f1f4b62c1b5"),
						ct:    dehex("920743a88d8cf6a09e1a3098e8be8edd09db136e9d543f215924043af8c7410f68ce6aa64fd2b1a176e7f6b3fd"),
					},
					{
						seq:   4,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d34"),
						nonce: dehex("ea4fd7a485ee5f1f4b62c1b3"),
						ct:    dehex("6b11380fcc708fc8589effb5b5e0394cbd441fa5e240b5500522150ca8265d65ff55479405af936e2349119dcd"),
					},
					{
						seq:   255,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d323535"),
						nonce: dehex("ea4fd7a485ee5f1f4b62c148"),
						ct:    dehex("d084eca50e7554bb97ba34c4482dfe32c9a2b7f3ab009c2d1b68ecbf97bee2d28cd94b6c829b96361f2701772d"),
					},
					{
						seq:   256,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d323536"),
						nonce: dehex("ea4fd7a485ee5f1f4b62c0b7"),
						ct:    dehex("247da592cc4ce834a94de2c79f5730ee49342470a021e4a4bc2bb77c53b17413e94d94f57b4fdaedcf97cfe7b1"),
					},
				},
				exports: []*exportInfo{
					{
						exporter_context: nil,
						L:                32,
						exported_value:   dehex("f03fbc82f321a0ab4840e487cb75d07aafd8e6f68485e4f7ff72b2f55ff24ad6"),
					},
					{
						exporter_context: dehex("00"),
						L:                32,
						exported_value:   dehex("1ce0cadec0a8f060f4b5070c8f8888dcdfefc2e35819df0cd559928a11ff0891"),
					},
					{
						exporter_context: dehex("54657374436f6e74657874"),
						L:                32,
						exported_value:   dehex("70c405c707102fd0041ea716090753be47d68d238b111d542846bd0d84ba907c"),
					},
				},
			},
			// https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.4.4
			{
				mode: AuthPSk,

				setup: &setupInfo{
					mode:   AuthPSk,
					kemId:  DHKEM_P256_HKDF_SHA256,
					kdfId:  KDF_HKDF_SHA512,
					aeadId: AEAD_AES_128_GCM,

					info:                 dehex("4f6465206f6e2061204772656369616e2055726e"),
					ikmE:                 dehex("37ae06a521cd555648c928d7af58ad2aa4a85e34b8cabd069e94ad55ab872cc8"),
					pkEm:                 dehex("04801740f4b1b35823f7fb2930eac2efc8c4893f34ba111c0bb976e3c7d5dc0aef5a7ef0bf4057949a140285f774f1efc53b3860936b92279a11b68395d898d138"),
					skEm:                 dehex("778f2254ae5d661d5c7fca8c4a7495a25bd13f26258e459159f3899df0de76c1"),
					ikmR:                 dehex("7466024b7e2d2366c3914d7833718f13afb9e3e45bcfbb510594d614ddd9b4e7"),
					pkRm:                 dehex("04a4ca7af2fc2cce48edbf2f1700983e927743a4e85bb5035ad562043e25d9a111cbf6f7385fac55edc5c9d2ca6ed351a5643de95c36748e11dbec98730f4d43e9"),
					skRm:                 dehex("00510a70fde67af487c093234fc4215c1cdec09579c4b30cc8e48cb530414d0e"),
					ikmS:                 dehex("ee27aaf99bf5cd8398e9de88ac09a82ac22cdb8d0905ab05c0f5fa12ba1709f3"),
					pkSm:                 dehex("04b59a4157a9720eb749c95f842a5e3e8acdccbe834426d405509ac3191e23f2165b5bb1f07a6240dd567703ae75e13182ee0f69fc102145cdb5abf681ff126d60"),
					skSm:                 dehex("d743b20821e6326f7a26684a4beed7088b35e392114480ca9f6c325079dcf10b"),
					psk:                  dehex("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82"),
					psk_id:               dehex("456e6e796e20447572696e206172616e204d6f726961"),
					enc:                  dehex("04801740f4b1b35823f7fb2930eac2efc8c4893f34ba111c0bb976e3c7d5dc0aef5a7ef0bf4057949a140285f774f1efc53b3860936b92279a11b68395d898d138"),
					shared_secret:        dehex("02bee8be0dda755846115db45071c0cf59c25722e015bde1c124de849c0fea52"),
					key_schedule_context: dehex("03713f73042575cebfd132f0cc4338523f8eae95c80a749f7cf3eb9436ff1c612ca62c37df27ca46d2cc162445a92c5f5fdc57bcde129ca7b1f284b0c12297c037ca221d77e229a9d11b654de7942d685069c633b2362ce3b3d8ea4891c9a2a87a4eb7cdb289ba5e2ecbf8cd2c8498bb4a383dc021454d70d46fcbbad1252ef4f9"),
					secret:               dehex("0f9df08908a6a3d06c8e934cd3f5313f9ebccd0986e316c0198bb48bed30dc3db2f3baab94fd40c2c285c7288c77e2255401ee2d5884306addf4296b93c238b3"),
					key:                  dehex("b68bb0e2fbf7431cedb46cc3b6f1fe9e"),
					base_nonce:           dehex("76af62719d33d39a1cb6be9f"),
					exporter_secret:      dehex("7f72308ae68c9a2b3862e686cb547b16d33d00fe482c770c4717d8b54e9b1e547244c3602bdd86d5a788a8443befea0a7658002b23f1c96a62a64986fffc511a"),
				},
				encryptions: []*encryptionInfo{
					{
						seq:   0,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d30"),
						nonce: dehex("76af62719d33d39a1cb6be9f"),
						ct:    dehex("840669634db51e28df54f189329c1b727fd303ae413f003020aff5e26276aaa910fc4296828cb9d862c2fd7d16"),
					},
					{
						seq:   1,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d31"),
						nonce: dehex("76af62719d33d39a1cb6be9e"),
						ct:    dehex("d4680a48158d9a75fd09355878d6e33997a36ee01d4a8f22032b22373b795a941b7b9c5205ff99e0ff284beef4"),
					},
					{
						seq:   2,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d32"),
						nonce: dehex("76af62719d33d39a1cb6be9d"),
						ct:    dehex("c45eb6597de2bac929a0f5d404ba9d2dc1ea031880930f1fd7a283f0a0cbebb35eac1a9ee0d1225f5e0f181571"),
					},
					{
						seq:   4,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d34"),
						nonce: dehex("76af62719d33d39a1cb6be9b"),
						ct:    dehex("4ee2482ad8d7d1e9b7e651c78b6ca26d3c5314d0711710ca62c2fd8bb8996d7d8727c157538d5493da696b61f8"),
					},
					{
						seq:   255,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d323535"),
						nonce: dehex("76af62719d33d39a1cb6be60"),
						ct:    dehex("65596b731df010c76a915c6271a438056ce65696459432eeafdae7b4cadb6290dd61e68edd4e40b659d2a8cbcc"),
					},
					{
						seq:   256,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d323536"),
						nonce: dehex("76af62719d33d39a1cb6bf9f"),
						ct:    dehex("9f659482ebc52f8303f9eac75656d807ec38ce2e50c72e3078cd13d86b30e3f890690a873277620f8a6a42d836"),
					},
				},
				exports: []*exportInfo{
					{
						exporter_context: nil,
						L:                32,
						exported_value:   dehex("c8c917e137a616d3d4e4c9fcd9c50202f366cb0d37862376bc79f9b72e8a8db9"),
					},
					{
						exporter_context: dehex("00"),
						L:                32,
						exported_value:   dehex("33a5d4df232777008a06d0684f23bb891cfaef702f653c8601b6ad4d08dddddf"),
					},
					{
						exporter_context: dehex("54657374436f6e74657874"),
						L:                32,
						exported_value:   dehex("bed80f2e54f1285895c4a3f3b3625e6206f78f1ed329a0cfb5864f7c139b3c6a"),
					},
				},
			},
		},
	},
	{
		name: "DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305",
		auths: []*authSuite{
			// https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.5.1
			{
				mode: Base,
				setup: &setupInfo{
					mode:                 Base,
					kemId:                DHKEM_P256_HKDF_SHA256,
					kdfId:                KDF_HKDF_SHA256,
					aeadId:               AEAD_CHACHA_20_POLY_1305,
					info:                 dehex("4f6465206f6e2061204772656369616e2055726e"),
					ikmE:                 dehex("f1f1a3bc95416871539ecb51c3a8f0cf608afb40fbbe305c0a72819d35c33f1f"),
					pkEm:                 dehex("04c07836a0206e04e31d8ae99bfd549380b072a1b1b82e563c935c095827824fc1559eac6fb9e3c70cd3193968994e7fe9781aa103f5b50e934b5b2f387e381291"),
					skEm:                 dehex("7550253e1147aae48839c1f8af80d2770fb7a4c763afe7d0afa7e0f42a5b3689"),
					ikmR:                 dehex("61092f3f56994dd424405899154a9918353e3e008171517ad576b900ddb275e7"),
					pkRm:                 dehex("04a697bffde9405c992883c5c439d6cc358170b51af72812333b015621dc0f40bad9bb726f68a5c013806a790ec716ab8669f84f6b694596c2987cf35baba2a006"),
					skRm:                 dehex("a4d1c55836aa30f9b3fbb6ac98d338c877c2867dd3a77396d13f68d3ab150d3b"),
					enc:                  dehex("04c07836a0206e04e31d8ae99bfd549380b072a1b1b82e563c935c095827824fc1559eac6fb9e3c70cd3193968994e7fe9781aa103f5b50e934b5b2f387e381291"),
					shared_secret:        dehex("806520f82ef0b03c823b7fc524b6b55a088f566b9751b89551c170f4113bd850"),
					key_schedule_context: dehex("00b738cd703db7b4106e93b4621e9a19c89c838e55964240e5d3f331aaf8b0d58b2e986ea1c671b61cf45eec134dac0bae58ec6f63e790b1400b47c33038b0269c"),
					secret:               dehex("fe891101629aa355aad68eff3cc5170d057eca0c7573f6575e91f9783e1d4506"),
					key:                  dehex("a8f45490a92a3b04d1dbf6cf2c3939ad8bfc9bfcb97c04bffe116730c9dfe3fc"),
					base_nonce:           dehex("726b4390ed2209809f58c693"),
					exporter_secret:      dehex("4f9bd9b3a8db7d7c3a5b9d44fdc1f6e37d5d77689ade5ec44a7242016e6aa205"),
				},
				encryptions: []*encryptionInfo{
					{
						seq:   0,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d30"),
						nonce: dehex("726b4390ed2209809f58c693"),
						ct:    dehex("6469c41c5c81d3aa85432531ecf6460ec945bde1eb428cb2fedf7a29f5a685b4ccb0d057f03ea2952a27bb458b"),
					},
					{
						seq:   1,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d31"),
						nonce: dehex("726b4390ed2209809f58c692"),
						ct:    dehex("f1564199f7e0e110ec9c1bcdde332177fc35c1adf6e57f8d1df24022227ffa8716862dbda2b1dc546c9d114374"),
					},
					{
						seq:   2,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d32"),
						nonce: dehex("726b4390ed2209809f58c691"),
						ct:    dehex("39de89728bcb774269f882af8dc5369e4f3d6322d986e872b3a8d074c7c18e8549ff3f85b6d6592ff87c3f310c"),
					},
					{
						seq:   4,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d34"),
						nonce: dehex("726b4390ed2209809f58c697"),
						ct:    dehex("bc104a14fbede0cc79eeb826ea0476ce87b9c928c36e5e34dc9b6905d91473ec369a08b1a25d305dd45c6c5f80"),
					},
					{
						seq:   255,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d323535"),
						nonce: dehex("726b4390ed2209809f58c66c"),
						ct:    dehex("8f2814a2c548b3be50259713c6724009e092d37789f6856553d61df23ebc079235f710e6af3c3ca6eaba7c7c6c"),
					},
					{
						seq:   256,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d323536"),
						nonce: dehex("726b4390ed2209809f58c793"),
						ct:    dehex("b45b69d419a9be7219d8c94365b89ad6951caf4576ea4774ea40e9b7047a09d6537d1aa2f7c12d6ae4b729b4d0"),
					},
				},
				exports: []*exportInfo{
					{
						exporter_context: nil,
						L:                32,
						exported_value:   dehex("9b13c510416ac977b553bf1741018809c246a695f45eff6d3b0356dbefe1e660"),
					},
					{
						exporter_context: dehex("00"),
						L:                32,
						exported_value:   dehex("6c8b7be3a20a5684edecb4253619d9051ce8583baf850e0cb53c402bdcaf8ebb"),
					},
					{
						exporter_context: dehex("54657374436f6e74657874"),
						L:                32,
						exported_value:   dehex("477a50d804c7c51941f69b8e32fe8288386ee1a84905fe4938d58972f24ac938"),
					},
				},
			},
			// https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.5.2
			{
				mode: PSk,
				setup: &setupInfo{
					mode:                 PSk,
					kemId:                DHKEM_P256_HKDF_SHA256,
					kdfId:                KDF_HKDF_SHA256,
					aeadId:               AEAD_CHACHA_20_POLY_1305,
					info:                 dehex("4f6465206f6e2061204772656369616e2055726e"),
					ikmE:                 dehex("e1a4e1d50c4bfcf890f2b4c7d6b2d2aca61368eddc3c84162df2856843e1057a"),
					pkEm:                 dehex("04f336578b72ad7932fe867cc4d2d44a718a318037a0ec271163699cee653fa805c1fec955e562663e0c2061bb96a87d78892bff0cc0bad7906c2d998ebe1a7246"),
					skEm:                 dehex("7d6e4e006cee68af9b3fdd583a0ee8962df9d59fab029997ee3f456cbc857904"),
					ikmR:                 dehex("ee51dec304abf993ef8fd52aacdd3b539108bbf6e491943266c1de89ec596a17"),
					pkRm:                 dehex("041eb8f4f20ab72661af369ff3231a733672fa26f385ffb959fd1bae46bfda43ad55e2d573b880831381d9367417f554ce5b2134fbba5235b44db465feffc6189e"),
					skRm:                 dehex("12ecde2c8bc2d5d7ed2219c71f27e3943d92b344174436af833337c557c300b3"),
					psk:                  dehex("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82"),
					psk_id:               dehex("456e6e796e20447572696e206172616e204d6f726961"),
					enc:                  dehex("04f336578b72ad7932fe867cc4d2d44a718a318037a0ec271163699cee653fa805c1fec955e562663e0c2061bb96a87d78892bff0cc0bad7906c2d998ebe1a7246"),
					shared_secret:        dehex("ac4f260dce4db6bf45435d9c92c0e11cfdd93743bd3075949975974cc2b3d79e"),
					key_schedule_context: dehex("01622b72afcc3795841596c67ea74400ca3b029374d7d5640bda367c5d67b3fbeb2e986ea1c671b61cf45eec134dac0bae58ec6f63e790b1400b47c33038b0269c"),
					secret:               dehex("858c8087a1c056db5811e85802f375bb0c19b9983204a1575de4803575d23239"),
					key:                  dehex("6d61cb330b7771168c8619498e753f16198aad9566d1f1c6c70e2bc1a1a8b142"),
					base_nonce:           dehex("0de7655fb65e1cd51a38864e"),
					exporter_secret:      dehex("754ca00235b245e72d1f722a7718e7145bd113050a2aa3d89586d4cb7514bfdb"),
				},
				encryptions: []*encryptionInfo{
					{
						seq:   0,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d30"),
						nonce: dehex("0de7655fb65e1cd51a38864e"),
						ct:    dehex("21433eaff24d7706f3ed5b9b2e709b07230e2b11df1f2b1fe07b3c70d5948a53d6fa5c8bed194020bd9df0877b"),
					},
					{
						seq:   1,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d31"),
						nonce: dehex("0de7655fb65e1cd51a38864f"),
						ct:    dehex("c74a764b4892072ea8c2c56b9bcd46c7f1e9ca8cb0a263f8b40c2ba59ac9c857033f176019562218769d3e0452"),
					},
					{
						seq:   2,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d32"),
						nonce: dehex("0de7655fb65e1cd51a38864c"),
						ct:    dehex("dc8cd68863474d6e9cbb6a659335a86a54e036249d41acf909e738c847ff2bd36fe3fcacda4ededa7032c0a220"),
					},
					{
						seq:   4,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d34"),
						nonce: dehex("0de7655fb65e1cd51a38864a"),
						ct:    dehex("cd54a8576353b1b9df366cb0cc042e46eef6f4cf01e205fe7d47e306b2fdd90f7185f289a26c613ca094e3be10"),
					},
					{
						seq:   255,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d323535"),
						nonce: dehex("0de7655fb65e1cd51a3886b1"),
						ct:    dehex("6324570c9d542c70c7e70570c1d8f4c52a89484746bf0625441890ededcc80c24ef2301c38bfd34d689d19f67d"),
					},
					{
						seq:   256,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d323536"),
						nonce: dehex("0de7655fb65e1cd51a38874e"),
						ct:    dehex("1ea6326c8098ed0437a553c466550114fb2ca1412cca7de98709b9ccdf19206e52c3d39180e2cf62b3e9f4baf4"),
					},
				},
				exports: []*exportInfo{
					{
						exporter_context: nil,
						L:                32,
						exported_value:   dehex("530bbc2f68f078dccc89cc371b4f4ade372c9472bafe4601a8432cbb934f528d"),
					},
					{
						exporter_context: dehex("00"),
						L:                32,
						exported_value:   dehex("6e25075ddcc528c90ef9218f800ca3dfe1b8ff4042de5033133adb8bd54c401d"),
					},
					{
						exporter_context: dehex("54657374436f6e74657874"),
						L:                32,
						exported_value:   dehex("6f6fbd0d1c7733f796461b3235a856cc34f676fe61ed509dfc18fa16efe6be78"),
					},
				},
			},
			// https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.5.3
			{
				mode: Auth,
				setup: &setupInfo{
					mode:                 Auth,
					kemId:                DHKEM_P256_HKDF_SHA256,
					kdfId:                KDF_HKDF_SHA256,
					aeadId:               AEAD_CHACHA_20_POLY_1305,
					info:                 dehex("4f6465206f6e2061204772656369616e2055726e"),
					ikmE:                 dehex("0ecd212019008138a31f9104d5dba76b9f8e34d5b996041fff9e3df221dd0d5d"),
					pkEm:                 dehex("040d5176aedba55bc41709261e9195c5146bb62d783031280775f32e507d79b5cbc5748b6be6359760c73cfe10ca19521af704ca6d91ff32fc0739527b9385d415"),
					skEm:                 dehex("085fd5d5e6ce6497c79df960cac93710006b76217d8bcfafbd2bb2c20ea03c42"),
					ikmR:                 dehex("d32236d8378b9563840653789eb7bc33c3c720e537391727bf1c812d0eac110f"),
					pkRm:                 dehex("0444f6ee41818d9fe0f8265bffd016b7e2dd3964d610d0f7514244a60dbb7a11ece876bb110a97a2ac6a9542d7344bf7d2bd59345e3e75e497f7416cf38d296233"),
					skRm:                 dehex("3cb2c125b8c5a81d165a333048f5dcae29a2ab2072625adad66dbb0f48689af9"),
					ikmS:                 dehex("0e6be0851283f9327295fd49858a8c8908ea9783212945eef6c598ee0a3cedbb"),
					pkSm:                 dehex("04265529a04d4f46ab6fa3af4943774a9f1127821656a75a35fade898a9a1b014f64d874e88cddb24c1c3d79004d3a587db67670ca357ff4fba7e8b56ec013b98b"),
					skSm:                 dehex("39b19402e742d48d319d24d68e494daa4492817342e593285944830320912519"),
					enc:                  dehex("040d5176aedba55bc41709261e9195c5146bb62d783031280775f32e507d79b5cbc5748b6be6359760c73cfe10ca19521af704ca6d91ff32fc0739527b9385d415"),
					shared_secret:        dehex("1a45aa4792f4b166bfee7eeab0096c1a6e497480e2261b2a59aad12f2768d469"),
					key_schedule_context: dehex("02b738cd703db7b4106e93b4621e9a19c89c838e55964240e5d3f331aaf8b0d58b2e986ea1c671b61cf45eec134dac0bae58ec6f63e790b1400b47c33038b0269c"),
					secret:               dehex("9193210815b87a4c5496c9d73e609a6c92665b5ea0d760866294906d089ebb57"),
					key:                  dehex("cf292f8a4313280a462ce55cde05b5aa5744fe4ca89a5d81b0146a5eaca8092d"),
					base_nonce:           dehex("7e45c21e20e869ae00492123"),
					exporter_secret:      dehex("dba6e307f71769ba11e2c687cc19592f9d436da0c81e772d7a8a9fd28e54355f"),
				},
				encryptions: []*encryptionInfo{
					{
						seq:   0,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d30"),
						nonce: dehex("7e45c21e20e869ae00492123"),
						ct:    dehex("25881f219935eec5ba70d7b421f13c35005734f3e4d959680270f55d71e2f5cb3bd2daced2770bf3d9d4916872,"),
					},
					{
						seq:   1,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d31"),
						nonce: dehex("7e45c21e20e869ae00492122"),
						ct:    dehex("653f0036e52a376f5d2dd85b3204b55455b7835c231255ae098d09ed138719b97185129786338ab6543f753193"),
					},
					{
						seq:   2,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d32"),
						nonce: dehex("7e45c21e20e869ae00492121"),
						ct:    dehex("60878706117f22180c788e62df6a595bc41906096a11a9513e84f0141e43239e81a98d7a235abc64112fcb8ddd"),
					},
					{
						seq:   4,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d34"),
						nonce: dehex("7e45c21e20e869ae00492127"),
						ct:    dehex("0f9094dd08240b5fa7a388b824d19d5b4b1e126cebfd67a062c32f9ba9f1f3866cc38de7df2702626e2ab65c0f"),
					},
					{
						seq:   255,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d323535"),
						nonce: dehex("7e45c21e20e869ae004921dc"),
						ct:    dehex("dd29319e08135c5f8401d6537a364e92172c0e3f095f3fd18923881d11c0a6839345dd0b54acd0edd8f8344792"),
					},
					{
						seq:   256,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d323536"),
						nonce: dehex("7e45c21e20e869ae00492023"),
						ct:    dehex("e2276ec5047bc4b6ed57d6da7da2fb47a77502f0a30f17d040247c73da336d722bc6c89adf68396a0912c6d152"),
					},
				},
				exports: []*exportInfo{
					{
						exporter_context: nil,
						L:                32,
						exported_value:   dehex("56c4d6c1d3a46c70fd8f4ecda5d27c70886e348efb51bd5edeaa39ff6ce34389"),
					},
					{
						exporter_context: dehex("00"),
						L:                32,
						exported_value:   dehex("d2d3e48ed76832b6b3f28fa84be5f11f09533c0e3c71825a34fb0f1320891b51"),
					},
					{
						exporter_context: dehex("54657374436f6e74657874"),
						L:                32,
						exported_value:   dehex("eb0d312b6263995b4c7761e64b688c215ffd6043ff3bad2368c862784cbe6eff"),
					},
				},
			},
			// https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.5.4
			{
				mode: AuthPSk,
				setup: &setupInfo{
					mode:                 AuthPSk,
					kemId:                DHKEM_P256_HKDF_SHA256,
					kdfId:                KDF_HKDF_SHA256,
					aeadId:               AEAD_CHACHA_20_POLY_1305,
					info:                 dehex("4f6465206f6e2061204772656369616e2055726e"),
					ikmE:                 dehex("f3a07f194703e321ef1f753a1b9fe27a498dfdfa309151d70bedd896c239c499"),
					pkEm:                 dehex("043539917ee26f8ae0aa5f784a387981b13de33124a3cde88b94672030183110f331400115855808244ff0c5b6ca6104483ac95724481d41bdcd9f15b430ad16f6"),
					skEm:                 dehex("11b7e4de2d919240616a31ab14944cced79bc2372108bb98f6792e3b645fe546"),
					ikmR:                 dehex("1240e55a0a03548d7f963ef783b6a7362cb505e6b31dfd04c81d9b294543bfbd"),
					pkRm:                 dehex("04d383fd920c42d018b9d57fd73a01f1eee480008923f67d35169478e55d2e8817068daf62a06b10e0aad4a9e429fa7f904481be96b79a9c231a33e956c20b81b6"),
					skRm:                 dehex("c29fc577b7e74d525c0043f1c27540a1248e4f2c8d297298e99010a92e94865c"),
					ikmS:                 dehex("ce2a0387a2eb8870a3a92c34a2975f0f3f271af4384d446c7dc1524a6c6c515a"),
					pkSm:                 dehex("0492cf8c9b144b742fe5a63d9a181a19d416f3ec8705f24308ad316564823c344e018bd7c03a33c926bb271b28ef5bf28c0ca00abff249fee5ef7f33315ff34fdb"),
					skSm:                 dehex("53541bd995f874a67f8bfd8038afa67fd68876801f42ff47d0dc2a4deea067ae"),
					psk:                  dehex("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82"),
					psk_id:               dehex("456e6e796e20447572696e206172616e204d6f726961"),
					enc:                  dehex("043539917ee26f8ae0aa5f784a387981b13de33124a3cde88b94672030183110f331400115855808244ff0c5b6ca6104483ac95724481d41bdcd9f15b430ad16f6"),
					shared_secret:        dehex("87584311791036a3019bc36803cdd42e9a8931a98b13c88835f2f8a9036a4fd6"),
					key_schedule_context: dehex("03622b72afcc3795841596c67ea74400ca3b029374d7d5640bda367c5d67b3fbeb2e986ea1c671b61cf45eec134dac0bae58ec6f63e790b1400b47c33038b0269c"),
					secret:               dehex("fe52b4412590e825ea2603fa88e145b2ee014b942a774b55fab4f081301f16f4"),
					key:                  dehex("31e140c8856941315d4067239fdc4ebe077fbf45a6fc78a61e7a6c8b3bacb10a"),
					base_nonce:           dehex("75838a8010d2e4760254dd56"),
					exporter_secret:      dehex("600895965755db9c5027f25f039a6e3e506c35b3b7084ce33c4a48d59ee1f0e3,"),
				},
				encryptions: []*encryptionInfo{
					{
						seq:   0,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d30"),
						nonce: dehex("75838a8010d2e4760254dd56"),
						ct:    dehex("9eadfa0f954835e7e920ffe56dec6b31a046271cf71fdda55db72926e1d8fae94cc6280fcfabd8db71eaa65c05"),
					},
					{
						seq:   1,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d31"),
						nonce: dehex("75838a8010d2e4760254dd57"),
						ct:    dehex("e357ad10d75240224d4095c9f6150a2ed2179c0f878e4f2db8ca95d365d174d059ff8c3eb38ea9a65cfc8eaeb8"),
					},
					{
						seq:   2,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d32"),
						nonce: dehex("75838a8010d2e4760254dd54"),
						ct:    dehex("2fa56d00f8dd479d67a2ec3308325cf3bbccaf102a64ffccdb006bd7dcb932685b9a7b49cdc094a85fec1da5ef"),
					},
					{
						seq:   4,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d34"),
						nonce: dehex("75838a8010d2e4760254dd52"),
						ct:    dehex("1fe9d6db14965003ed81a39abf240f9cd7c5a454bca0d69ef9a2de16d537364fbbf110b9ef11fa4a7a0172f0ce"),
					},
					{
						seq:   255,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d323535"),
						nonce: dehex("75838a8010d2e4760254dda9"),
						ct:    dehex("eaf4041a5c9122b22d1f8d698eeffe45d64b4ae33d0ddca3a4cdf4a5f595acc95a1a9334d06cc4d000df6aaad6"),
					},
					{
						seq:   256,
						pt:    dehex("4265617574792069732074727574682c20747275746820626561757479"),
						aad:   dehex("436f756e742d323536"),
						nonce: dehex("75838a8010d2e4760254dc56"),
						ct:    dehex("fb857f4185ce5286c1a52431867537204963ea66a3eee8d2a74419fd8751faee066d08277ac7880473aa4143ba"),
					},
				},
				exports: []*exportInfo{
					{
						exporter_context: nil,
						L:                32,
						exported_value:   dehex("c52b4592cd33dd38b2a3613108ddda28dcf7f03d30f2a09703f758bfa8029c9a"),
					},
					{
						exporter_context: dehex("00"),
						L:                32,
						exported_value:   dehex("2f03bebc577e5729e148554991787222b5c2a02b77e9b1ac380541f710e5a318"),
					},
					{
						exporter_context: dehex("54657374436f6e74657874"),
						L:                32,
						exported_value:   dehex("e01dd49e8bfc3d9216abc1be832f0418adf8b47a7b5a330a7436c31e33d765d7"),
					},
				},
			},
		},
	},
}

func setup(t *testing.T, s *setupInfo) (*ReceiverContext, *SenderContext) {
	t.Helper()

	cipherSuite := &CipherSuite{
		KDF:  s.kdfId,
		KEM:  s.kemId,
		AEAD: s.aeadId,
	}

	kem := kems[s.kemId]

	ephemeralPrivateKey, err := kem.DeriveKeyPair(s.ikmE)
	require.NoError(t, err)
	if !bytes.Equal(s.skEm, ephemeralPrivateKey.D.Bytes()) {
		print("hi")
	}
	require.EqualValues(t, s.skEm, ephemeralPrivateKey.D.Bytes())
	require.EqualValues(t, s.pkEm, ephemeralPrivateKey.PublicKey.ToAffineUncompressed())

	receiverPrivateKey, err := kem.DeriveKeyPair(s.ikmR)
	require.NoError(t, err)

	require.EqualValues(t, s.skRm, receiverPrivateKey.D.Bytes())
	require.EqualValues(t, s.pkRm, receiverPrivateKey.PublicKey.ToAffineUncompressed())

	var sharedSecret []byte
	var ephemeralPublicKey PublicKey
	var senderPrivateKey *PrivateKey
	if s.mode == Auth || s.mode == AuthPSk {
		senderPrivateKey, err = kem.DeriveKeyPair(s.ikmS)
		require.NoError(t, err)

		require.EqualValues(t, s.skEm, ephemeralPrivateKey.D.Bytes())
		require.EqualValues(t, s.pkEm, ephemeralPrivateKey.PublicKey.ToAffineUncompressed())

		sharedSecret, ephemeralPublicKey, err = kem.AuthEncapWithIKM(receiverPrivateKey.PublicKey, senderPrivateKey, s.ikmE)
		require.NoError(t, err)
	} else {
		sharedSecret, ephemeralPublicKey, err = kem.EncapWithIKM(receiverPrivateKey.PublicKey, s.ikmE)
		require.NoError(t, err)
	}
	require.EqualValues(t, s.enc, ephemeralPublicKey.ToAffineUncompressed())
	require.EqualValues(t, s.shared_secret, sharedSecret)

	ctx, keyScheduleCtx, err := keySchedule(ReceiverRole, cipherSuite, s.mode, sharedSecret, s.info, s.psk, s.psk_id)
	require.NoError(t, err)
	require.EqualValues(t, s.key_schedule_context, keyScheduleCtx.Marshal())
	require.EqualValues(t, s.secret, ctx.secret)
	require.EqualValues(t, s.base_nonce, ctx.baseNonce)
	require.EqualValues(t, s.key, ctx.key)
	require.EqualValues(t, s.exporter_secret, ctx.exporterSecret)

	receiverContext := &ReceiverContext{receiverPrivateKey, ctx}
	var senderContext *SenderContext
	if senderPrivateKey != nil {
		ctx, _, err := keySchedule(SenderRole, cipherSuite, s.mode, sharedSecret, s.info, s.psk, s.psk_id)
		require.NoError(t, err)
		senderContext = &SenderContext{senderPrivateKey, ctx}
	}
	return receiverContext, senderContext
}

func openCiphertext(t *testing.T, receiver *ReceiverContext, tt *encryptionInfo) {
	t.Helper()
	receiver.c.sequence = tt.seq
	require.NotContains(t, receiver.c.nonces, tt.nonce)
	decrypted, err := receiver.Open(tt.ct, tt.aad)
	require.NoError(t, err)
	require.EqualValues(t, tt.pt, decrypted)
	require.Equal(t, tt.seq+1, receiver.c.sequence)
	require.Contains(t, receiver.c.nonces, tt.nonce)
}

func sealPlaintext(t *testing.T, sender *SenderContext, tt *encryptionInfo) {
	t.Helper()
	sender.c.sequence = tt.seq
	require.NotContains(t, sender.c.nonces, tt.nonce)
	ciphertext, err := sender.Seal(tt.pt, tt.aad)
	require.NoError(t, err)
	require.EqualValues(t, tt.ct, ciphertext)
	require.Equal(t, tt.seq+1, sender.c.sequence)
	require.Contains(t, sender.c.nonces, tt.nonce)
}

// Test https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A
func TestRFCTestVectors(t *testing.T) {
	t.Parallel()
	for _, suiteTest := range tests {
		for _, authTest := range suiteTest.auths {
			s := suiteTest
			a := authTest
			t.Run(fmt.Sprintf("%s | mode: %v", s.name, a.mode), func(t *testing.T) {
				t.Parallel()
				for _, test := range a.encryptions {
					tt := test
					t.Run(fmt.Sprintf("running encryption test for seq %d", tt.seq), func(t *testing.T) {
						t.Parallel()
						receiver, sender := setup(t, a.setup)
						openCiphertext(t, receiver, tt)
						if a.mode == Auth || a.mode == AuthPSk {
							require.NotNil(t, sender)
							sealPlaintext(t, sender, tt)
						}
					})
				}

				for i, test := range a.exports {
					tt := test
					ii := i
					t.Run(fmt.Sprintf("running export test for iteration %d", ii), func(t *testing.T) {
						t.Parallel()
						receiver, sender := setup(t, a.setup)
						secret, err := receiver.Export(tt.exporter_context, tt.L)
						require.NoError(t, err)
						require.EqualValues(t, tt.exported_value, secret)
						if a.mode == Auth || a.mode == AuthPSk {
							require.NotNil(t, sender)
							secret, err := sender.Export(tt.exporter_context, tt.L)
							require.NoError(t, err)
							require.EqualValues(t, tt.exported_value, secret)
						}
					})
				}
			})
		}
	}
}
