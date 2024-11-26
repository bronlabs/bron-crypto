package noninteractive_signing_test

import (
	nativeEddsa "crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/combinatorics"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	hashingBip340 "github.com/copperexchange/krypton-primitives/pkg/hashing/bip340"
	"github.com/copperexchange/krypton-primitives/pkg/hashing/poseidon"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/bip340"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/mina"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/zilliqa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/keygen/trusted_dealer"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/signing"
	noninteractive_signing "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/signing/noninteractive"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/signing/noninteractive/testutils"
)

var configs = []struct{ nParticipants, nPreSigners, nThreshold int }{
	{nParticipants: 3, nPreSigners: 3, nThreshold: 2},
	{nParticipants: 3, nPreSigners: 2, nThreshold: 2},
	{nParticipants: 5, nPreSigners: 4, nThreshold: 3},
}

func Test_SignNonInteractiveThresholdEdDSA(t *testing.T) {
	t.Parallel()

	variant := vanilla.NewEdDsaCompatibleVariant()
	curve := edwards25519.NewCurve()
	hashFunc := sha512.New
	cipherSuite, err := ttu.MakeSigningSuite(curve, hashFunc)
	require.NoError(t, err)

	prng := crand.Reader
	sid := []byte("sessionId")
	message := []byte("Lorem ipsum")
	transcriptAppLabel := "Lindell2022NonInteractiveSignTest"

	for _, cfg := range configs {
		n := cfg.nParticipants
		nPresigners := cfg.nPreSigners
		threshold := cfg.nThreshold
		t.Run(fmt.Sprintf("EdDSA (%d,%d,%d)", n, nPresigners, threshold), func(t *testing.T) {
			t.Parallel()

			identities, err := ttu.MakeTestIdentities(cipherSuite, n)
			require.NoError(t, err)

			protocolConfig, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, threshold, identities)
			require.NoError(t, err)

			shards, err := trusted_dealer.Keygen(protocolConfig, prng)
			require.NoError(t, err)

			aliceShard, exists := shards.Get(identities[0])
			require.True(t, exists)
			publicKey := aliceShard.PublicKey()
			var publicKeyShares *tsignatures.PartialPublicKeys
			for _, shard := range shards.Iter() {
				publicKeyShares = shard.PublicKeyShares
				break
			}

			N := make([]int, n)
			for i := range n {
				N[i] = i
			}
			preSignersCombinations, err := combinatorics.Combinations(N, uint(nPresigners))
			require.NoError(t, err)
			for _, preSignersCombination := range preSignersCombinations {
				preSignersIdentities := make([]types.IdentityKey, len(preSignersCombination))
				for i, p := range preSignersCombination {
					preSignersIdentities[i] = identities[p]
				}

				preSignerstranscripts := ttu.MakeTranscripts(transcriptAppLabel, preSignersIdentities)
				preSigners := testutils.MakePreGenParticipants(t, preSignersIdentities, sid, protocolConfig, preSignerstranscripts)
				ppms := testutils.DoLindell2022PreGen(t, preSigners)

				PS := make([]int, len(preSigners))
				for i := range preSigners {
					PS[i] = i
				}
				cosignersCombinations, err := combinatorics.Combinations(PS, uint(threshold))
				require.NoError(t, err)
				for _, cosignerCombination := range cosignersCombinations {
					cosignersIdentities := make([]types.IdentityKey, len(cosignerCombination))
					for i, c := range cosignerCombination {
						cosignersIdentities[i] = preSignersIdentities[c]
					}

					partialSignatures := hashmap.NewHashableHashMap[types.IdentityKey, *tschnorr.PartialSignature]()
					for _, c := range cosignerCombination {
						shard, exists := shards.Get(preSignersIdentities[c])
						require.True(t, exists)

						cosigner, err := noninteractive_signing.NewCosigner(preSignersIdentities[c].(types.AuthKey), shard, protocolConfig, hashset.NewHashableHashSet(cosignersIdentities...), ppms[c], variant, nil, prng)
						require.NoError(t, err)

						psig, err := cosigner.ProducePartialSignature(message)
						require.NoError(t, err)

						partialSignatures.Put(preSignersIdentities[c], psig)
					}

					signature, err := signing.Aggregate(variant, protocolConfig, message, publicKeyShares, &schnorr.PublicKey{A: publicKey}, partialSignatures)
					require.NoError(t, err)

					valid := nativeEddsa.Verify(
						publicKey.ToAffineCompressed(),
						message,
						slices.Concat(signature.R.ToAffineCompressed(), bitstring.ReverseBytes(signature.S.Bytes())),
					)
					require.True(t, valid)
				}
			}
		})
	}
}

func Test_SignNonInteractiveThresholdTaproot(t *testing.T) {
	t.Parallel()

	variant := bip340.NewTaprootVariant()
	curve := k256.NewCurve()
	hashFunc := hashingBip340.NewBip340HashChallenge
	cipherSuite, err := ttu.MakeSigningSuite(curve, hashFunc)
	require.NoError(t, err)

	prng := crand.Reader
	sid := []byte("sessionId")
	message := []byte("Lorem ipsum")
	transcriptAppLabel := "Lindell2022NonInteractiveSignTest"

	for _, cfg := range configs {
		n := cfg.nParticipants
		nPresigners := cfg.nPreSigners
		threshold := cfg.nThreshold
		t.Run(fmt.Sprintf("Taproot (%d,%d,%d)", n, nPresigners, threshold), func(t *testing.T) {
			t.Parallel()

			identities, err := ttu.MakeTestIdentities(cipherSuite, n)
			require.NoError(t, err)

			protocolConfig, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, threshold, identities)
			require.NoError(t, err)

			shards, err := trusted_dealer.Keygen(protocolConfig, prng)
			require.NoError(t, err)

			aliceShard, exists := shards.Get(identities[0])
			require.True(t, exists)
			publicKey := aliceShard.PublicKey()
			var publicKeyShares *tsignatures.PartialPublicKeys
			for _, shard := range shards.Iter() {
				publicKeyShares = shard.PublicKeyShares
				break
			}

			N := make([]int, n)
			for i := range n {
				N[i] = i
			}
			preSignersCombinations, err := combinatorics.Combinations(N, uint(nPresigners))
			require.NoError(t, err)
			for _, preSignersCombination := range preSignersCombinations {
				preSignersIdentities := make([]types.IdentityKey, len(preSignersCombination))
				for i, p := range preSignersCombination {
					preSignersIdentities[i] = identities[p]
				}

				preSignerstranscripts := ttu.MakeTranscripts(transcriptAppLabel, preSignersIdentities)
				preSigners := testutils.MakePreGenParticipants(t, preSignersIdentities, sid, protocolConfig, preSignerstranscripts)
				ppms := testutils.DoLindell2022PreGen(t, preSigners)

				ps := make([]int, len(preSigners))
				for i := range preSigners {
					ps[i] = i
				}
				cosignersCombinations, err := combinatorics.Combinations(ps, uint(threshold))
				require.NoError(t, err)
				for _, cosignerCombination := range cosignersCombinations {
					cosignersIdentities := make([]types.IdentityKey, len(cosignerCombination))
					for i, c := range cosignerCombination {
						cosignersIdentities[i] = preSignersIdentities[c]
					}

					partialSignatures := hashmap.NewHashableHashMap[types.IdentityKey, *tschnorr.PartialSignature]()
					for _, c := range cosignerCombination {
						shard, exists := shards.Get(preSignersIdentities[c])
						require.True(t, exists)

						cosigner, err := noninteractive_signing.NewCosigner(preSignersIdentities[c].(types.AuthKey), shard, protocolConfig, hashset.NewHashableHashSet(cosignersIdentities...), ppms[c], variant, nil, prng)
						require.NoError(t, err)

						psig, err := cosigner.ProducePartialSignature(message)
						require.NoError(t, err)

						partialSignatures.Put(preSignersIdentities[c], psig)
					}

					signature, err := signing.Aggregate(variant, protocolConfig, message, publicKeyShares, &schnorr.PublicKey{A: publicKey}, partialSignatures)
					require.NoError(t, err)

					err = bip340.Verify(&bip340.PublicKey{A: publicKey}, signature, message)
					require.NoError(t, err)
				}
			}
		})
	}
}

func Test_SignNonInteractiveThresholdMina(t *testing.T) {
	t.Parallel()

	networkId := mina.MainNet
	variant := mina.NewMinaVariant(networkId)
	curve := pallas.NewCurve()
	hashFunc := poseidon.NewLegacyHash
	identitiesHashFunc := sha256.New

	identityCipherSuite, err := ttu.MakeSigningSuite(curve, identitiesHashFunc)
	require.NoError(t, err)

	cipherSuite, err := ttu.MakeSigningSuite(curve, hashFunc)
	require.NoError(t, err)

	prng := crand.Reader
	sid := []byte("sessionId")
	message := new(mina.ROInput).Init()
	message.AddString("Lorem ipsum")
	transcriptAppLabel := "Lindell2022NonInteractiveSignTest"

	for _, cfg := range configs {
		n := cfg.nParticipants
		nPresigners := cfg.nPreSigners
		threshold := cfg.nThreshold
		t.Run(fmt.Sprintf("Mina (%d,%d,%d)", n, nPresigners, threshold), func(t *testing.T) {
			t.Parallel()

			identities, err := ttu.MakeTestIdentities(identityCipherSuite, n)
			require.NoError(t, err)

			protocolConfig, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, threshold, identities)
			require.NoError(t, err)

			shards, err := trusted_dealer.Keygen(protocolConfig, prng)
			require.NoError(t, err)

			aliceShard, exists := shards.Get(identities[0])
			require.True(t, exists)
			publicKey := aliceShard.PublicKey()
			var publicKeyShares *tsignatures.PartialPublicKeys
			for _, shard := range shards.Iter() {
				publicKeyShares = shard.PublicKeyShares
				break
			}

			N := make([]int, n)
			for i := range n {
				N[i] = i
			}
			preSignersCombinations, err := combinatorics.Combinations(N, uint(nPresigners))
			require.NoError(t, err)
			for _, preSignersCombination := range preSignersCombinations {
				preSignersIdentities := make([]types.IdentityKey, len(preSignersCombination))
				for i, p := range preSignersCombination {
					preSignersIdentities[i] = identities[p]
				}

				preSignerstranscripts := ttu.MakeTranscripts(transcriptAppLabel, preSignersIdentities)
				preSigners := testutils.MakePreGenParticipants(t, preSignersIdentities, sid, protocolConfig, preSignerstranscripts)
				ppms := testutils.DoLindell2022PreGen(t, preSigners)

				ps := make([]int, len(preSigners))
				for i := range preSigners {
					ps[i] = i
				}
				cosignersCombinations, err := combinatorics.Combinations(ps, uint(threshold))
				require.NoError(t, err)
				for _, cosignerCombination := range cosignersCombinations {
					cosignersIdentities := make([]types.IdentityKey, len(cosignerCombination))
					for i, c := range cosignerCombination {
						cosignersIdentities[i] = preSignersIdentities[c]
					}

					partialSignatures := hashmap.NewHashableHashMap[types.IdentityKey, *tschnorr.PartialSignature]()
					for _, c := range cosignerCombination {
						shard, exists := shards.Get(preSignersIdentities[c])
						require.True(t, exists)

						cosigner, err := noninteractive_signing.NewCosigner(preSignersIdentities[c].(types.AuthKey), shard, protocolConfig, hashset.NewHashableHashSet(cosignersIdentities...), ppms[c], variant, nil, prng)
						require.NoError(t, err)

						psig, err := cosigner.ProducePartialSignature(message)
						require.NoError(t, err)

						partialSignatures.Put(preSignersIdentities[c], psig)
					}

					signature, err := signing.Aggregate(variant, protocolConfig, message, publicKeyShares, &schnorr.PublicKey{A: publicKey}, partialSignatures)
					require.NoError(t, err)

					err = mina.Verify(&mina.PublicKey{A: publicKey}, signature, message, networkId)
					require.NoError(t, err)
				}
			}
		})
	}
}

func Test_SignNonInteractiveThresholdZilliqa(t *testing.T) {
	t.Parallel()

	variant := zilliqa.NewZilliqaVariant()
	curve := k256.NewCurve()
	hashFunc := sha256.New
	cipherSuite, err := ttu.MakeSigningSuite(curve, hashFunc)
	require.NoError(t, err)

	prng := crand.Reader
	sid := []byte("sessionId")
	message := []byte("Lorem ipsum")
	transcriptAppLabel := "Lindell2022NonInteractiveSignTest"

	for _, cfg := range configs {
		n := cfg.nParticipants
		nPresigners := cfg.nPreSigners
		threshold := cfg.nThreshold
		t.Run(fmt.Sprintf("Zilliqa (%d,%d,%d)", n, nPresigners, threshold), func(t *testing.T) {
			t.Parallel()

			identities, err := ttu.MakeTestIdentities(cipherSuite, n)
			require.NoError(t, err)

			protocolConfig, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, threshold, identities)
			require.NoError(t, err)

			shards, err := trusted_dealer.Keygen(protocolConfig, prng)
			require.NoError(t, err)

			aliceShard, exists := shards.Get(identities[0])
			require.True(t, exists)
			publicKey := aliceShard.PublicKey()
			var publicKeyShares *tsignatures.PartialPublicKeys
			for _, shard := range shards.Iter() {
				publicKeyShares = shard.PublicKeyShares
				break
			}

			N := make([]int, n)
			for i := range n {
				N[i] = i
			}
			preSignersCombinations, err := combinatorics.Combinations(N, uint(nPresigners))
			require.NoError(t, err)
			for _, preSignersCombination := range preSignersCombinations {
				preSignersIdentities := make([]types.IdentityKey, len(preSignersCombination))
				for i, p := range preSignersCombination {
					preSignersIdentities[i] = identities[p]
				}

				preSignerstranscripts := ttu.MakeTranscripts(transcriptAppLabel, preSignersIdentities)
				preSigners := testutils.MakePreGenParticipants(t, preSignersIdentities, sid, protocolConfig, preSignerstranscripts)
				ppms := testutils.DoLindell2022PreGen(t, preSigners)

				ps := make([]int, len(preSigners))
				for i := range preSigners {
					ps[i] = i
				}
				cosignersCombinations, err := combinatorics.Combinations(ps, uint(threshold))
				require.NoError(t, err)
				for _, cosignerCombination := range cosignersCombinations {
					cosignersIdentities := make([]types.IdentityKey, len(cosignerCombination))
					for i, c := range cosignerCombination {
						cosignersIdentities[i] = preSignersIdentities[c]
					}

					partialSignatures := hashmap.NewHashableHashMap[types.IdentityKey, *tschnorr.PartialSignature]()
					for _, c := range cosignerCombination {
						shard, exists := shards.Get(preSignersIdentities[c])
						require.True(t, exists)

						cosigner, err := noninteractive_signing.NewCosigner(preSignersIdentities[c].(types.AuthKey), shard, protocolConfig, hashset.NewHashableHashSet(cosignersIdentities...), ppms[c], variant, nil, prng)
						require.NoError(t, err)

						psig, err := cosigner.ProducePartialSignature(message)
						require.NoError(t, err)

						partialSignatures.Put(preSignersIdentities[c], psig)
					}

					signature, err := signing.Aggregate(variant, protocolConfig, message, publicKeyShares, &schnorr.PublicKey{A: publicKey}, partialSignatures)
					require.NoError(t, err)

					err = zilliqa.Verify(&zilliqa.PublicKey{A: publicKey}, signature, message)
					require.NoError(t, err)
				}
			}
		})
	}
}
