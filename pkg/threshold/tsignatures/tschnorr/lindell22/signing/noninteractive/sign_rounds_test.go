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
	"gonum.org/v1/gonum/stat/combin"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	hashingBip340 "github.com/copperexchange/krypton-primitives/pkg/hashing/bip340"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/bip340"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/zilliqa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
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

	variant := schnorr.NewEdDsaCompatibleVariant()
	curve := edwards25519.NewCurve()
	hashFunc := sha512.New
	cipherSuite, err := ttu.MakeSignatureProtocol(curve, hashFunc)
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

			preSignersCombinations := combin.Combinations(n, nPresigners)
			for _, preSignersCombination := range preSignersCombinations {
				preSignersIdentities := make([]types.IdentityKey, len(preSignersCombination))
				for i, p := range preSignersCombination {
					preSignersIdentities[i] = identities[p]
				}

				preSignerstranscripts := ttu.MakeTranscripts(transcriptAppLabel, preSignersIdentities)

				preSigners, err := testutils.MakePreGenParticipants(preSignersIdentities, sid, protocolConfig, preSignerstranscripts)
				require.NoError(t, err)

				ppms, err := testutils.DoLindell2022PreGen(preSigners)
				require.NoError(t, err)

				cosignersCombinations := combin.Combinations(len(preSigners), threshold)
				for _, cosignerCombination := range cosignersCombinations {
					cosignersIdentities := make([]types.IdentityKey, len(cosignerCombination))
					for i, c := range cosignerCombination {
						cosignersIdentities[i] = preSignersIdentities[c]
					}

					partialSignatures := make([]*lindell22.PartialSignature, len(cosignersIdentities))
					for i, c := range cosignerCombination {
						shard, exists := shards.Get(preSignersIdentities[c])
						require.True(t, exists)

						cosigner, err := noninteractive_signing.NewCosigner(sid, preSignersIdentities[c].(types.AuthKey), shard, protocolConfig, hashset.NewHashableHashSet(cosignersIdentities...), ppms[c], variant, nil, prng)
						require.NoError(t, err)

						partialSignatures[i], err = cosigner.ProducePartialSignature(message)
						require.NoError(t, err)
					}

					signature, err := signing.Aggregate(variant, partialSignatures...)
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

	variant := schnorr.NewTaprootVariant()
	curve := k256.NewCurve()
	hashFunc := hashingBip340.NewBip340HashChallenge
	cipherSuite, err := ttu.MakeSignatureProtocol(curve, hashFunc)
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

			preSignersCombinations := combin.Combinations(n, nPresigners)
			for _, preSignersCombination := range preSignersCombinations {
				preSignersIdentities := make([]types.IdentityKey, len(preSignersCombination))
				for i, p := range preSignersCombination {
					preSignersIdentities[i] = identities[p]
				}

				preSignerstranscripts := ttu.MakeTranscripts(transcriptAppLabel, preSignersIdentities)

				preSigners, err := testutils.MakePreGenParticipants(preSignersIdentities, sid, protocolConfig, preSignerstranscripts)
				require.NoError(t, err)

				ppms, err := testutils.DoLindell2022PreGen(preSigners)
				require.NoError(t, err)

				cosignersCombinations := combin.Combinations(len(preSigners), threshold)
				for _, cosignerCombination := range cosignersCombinations {
					cosignersIdentities := make([]types.IdentityKey, len(cosignerCombination))
					for i, c := range cosignerCombination {
						cosignersIdentities[i] = preSignersIdentities[c]
					}

					partialSignatures := make([]*lindell22.PartialSignature, len(cosignersIdentities))
					for i, c := range cosignerCombination {
						shard, exists := shards.Get(preSignersIdentities[c])
						require.True(t, exists)

						cosigner, err := noninteractive_signing.NewCosigner(sid, preSignersIdentities[c].(types.AuthKey), shard, protocolConfig, hashset.NewHashableHashSet(cosignersIdentities...), ppms[c], variant, nil, prng)
						require.NoError(t, err)

						partialSignatures[i], err = cosigner.ProducePartialSignature(message)
						require.NoError(t, err)
					}

					signature, err := signing.Aggregate(variant, partialSignatures...)
					require.NoError(t, err)

					err = bip340.Verify(&bip340.PublicKey{A: publicKey}, signature, message)
					require.NoError(t, err)
				}
			}
		})
	}
}

func Test_SignNonInteractiveThresholdZilliqa(t *testing.T) {
	t.Parallel()

	variant := schnorr.NewZilliqaVariant()
	curve := k256.NewCurve()
	hashFunc := sha256.New
	cipherSuite, err := ttu.MakeSignatureProtocol(curve, hashFunc)
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

			preSignersCombinations := combin.Combinations(n, nPresigners)
			for _, preSignersCombination := range preSignersCombinations {
				preSignersIdentities := make([]types.IdentityKey, len(preSignersCombination))
				for i, p := range preSignersCombination {
					preSignersIdentities[i] = identities[p]
				}

				preSignerstranscripts := ttu.MakeTranscripts(transcriptAppLabel, preSignersIdentities)

				preSigners, err := testutils.MakePreGenParticipants(preSignersIdentities, sid, protocolConfig, preSignerstranscripts)
				require.NoError(t, err)

				ppms, err := testutils.DoLindell2022PreGen(preSigners)
				require.NoError(t, err)

				cosignersCombinations := combin.Combinations(len(preSigners), threshold)
				for _, cosignerCombination := range cosignersCombinations {
					cosignersIdentities := make([]types.IdentityKey, len(cosignerCombination))
					for i, c := range cosignerCombination {
						cosignersIdentities[i] = preSignersIdentities[c]
					}

					partialSignatures := make([]*lindell22.PartialSignature, len(cosignersIdentities))
					for i, c := range cosignerCombination {
						shard, exists := shards.Get(preSignersIdentities[c])
						require.True(t, exists)

						cosigner, err := noninteractive_signing.NewCosigner(sid, preSignersIdentities[c].(types.AuthKey), shard, protocolConfig, hashset.NewHashableHashSet(cosignersIdentities...), ppms[c], variant, nil, prng)
						require.NoError(t, err)

						partialSignatures[i], err = cosigner.ProducePartialSignature(message)
						require.NoError(t, err)
					}

					signature, err := signing.Aggregate(variant, partialSignatures...)
					require.NoError(t, err)

					err = zilliqa.Verify(&zilliqa.PublicKey{A: publicKey}, signature, message)
					require.NoError(t, err)
				}
			}
		})
	}
}
