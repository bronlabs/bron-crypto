package benchmark_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/bls12381"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	test_utils_integration "github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashset"
	lindell17_noninteractive_signing "github.com/copperexchange/knox-primitives/pkg/knox/noninteractive_signing/tecdsa/lindell17"
	noninteractive_signing_lindell17_test_utils "github.com/copperexchange/knox-primitives/pkg/knox/noninteractive_signing/tecdsa/lindell17/test_utils"
	lindell22_noninteractive_signing "github.com/copperexchange/knox-primitives/pkg/knox/noninteractive_signing/tschnorr/lindell22"
	noninteractive_signing_lindell22_test_utils "github.com/copperexchange/knox-primitives/pkg/knox/noninteractive_signing/tschnorr/lindell22/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/signatures/bls"
	"github.com/copperexchange/knox-primitives/pkg/signatures/ecdsa"
	"github.com/copperexchange/knox-primitives/pkg/signatures/eddsa"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tbls/boldyreva02"
	bls_trusted_dealer "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tbls/boldyreva02/keygen/trusted_dealer"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tbls/boldyreva02/signing/aggregation"
	boldyreva02_test_utils "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tbls/boldyreva02/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23"
	dkls23_dkg_test_utils "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23/keygen/dkg/test_utils"
	dkls23_test_utils "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17"
	lindell17_trusted_dealer "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17/keygen/trusted_dealer"
	lindell17_test_utils "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22"
	lindell22_trusted_dealer "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/keygen/trusted_dealer"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/signing"
	lindell22_interactive_test_utils "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/signing/interactive/test_utils"
	lindell22_signing_test_utils "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/signing/interactive/test_utils"
	lindell22_dkg_test_utils "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/test_utils"
	"golang.org/x/crypto/sha3"

	"github.com/stretchr/testify/require"
	"testing"
)

type (
	G1 = *bls12381.PointG1
	G2 = *bls12381.PointG2
)

var (
	h                  = sha3.New256
	t                  = 2
	n                  = 3
	message            = []byte("message")
	sid                = []byte("sid")
	numberOfSignatures = 10000
	tau                = 10000
)

func BenchmarkDkg(b *testing.B) {
	b.Run("Lindell22", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			cipherSuite := &integration.CipherSuite{
				Curve: edwards25519.New(),
				Hash:  h,
			}
			identities, err := test_utils.MakeIdentities(cipherSuite, n)
			require.NoError(b, err)
			cohortConfig, err := test_utils_integration.MakeCohortProtocol(cipherSuite, protocols.FROST, identities, t, identities)
			require.NoError(b, err)
			_, err = lindell22_dkg_test_utils.DoKeygen(edwards25519.New(), identities, cohortConfig)
			require.NoError(b, err)
		}
	})
	b.Run("Dkls23", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, _, _, err := dkls23_dkg_test_utils.KeyGen(k256.New(), h, t, n, nil, nil)
			require.NoError(b, err)
		}
	})
	b.Run("Boldyreva02", func(b *testing.B) {
		pointInK := new(G1)
		for i := 0; i < b.N; i++ {
			cipherSuite := &integration.CipherSuite{
				Curve: (*pointInK).Curve(),
				Hash:  h,
			}
			identities, err := test_utils.MakeIdentities(cipherSuite, n)
			require.NoError(b, err)
			cohortConfig, err := test_utils_integration.MakeCohortProtocol(cipherSuite, protocols.FROST, identities, t, identities)
			require.NoError(b, err)
			_, err = boldyreva02_test_utils.DoKeygen[G1]((*pointInK).Curve(), identities, cohortConfig)
			require.NoError(b, err)
		}
	})
}

func lindell22QuickKeygen(b *testing.B) ([]integration.IdentityKey, *integration.CohortConfig, map[helper_types.IdentityHash]*lindell22.Shard) {
	cipherSuite := &integration.CipherSuite{
		Curve: edwards25519.New(),
		Hash:  sha512.New,
	}
	identities, err := test_utils.MakeIdentities(cipherSuite, n)
	require.NoError(b, err)
	cohortConfig := &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: hashset.NewHashSet(identities),
		Protocol: &integration.ProtocolConfig{
			Name:                 protocols.LINDELL22,
			Threshold:            t,
			TotalParties:         n,
			SignatureAggregators: hashset.NewHashSet(identities),
		},
	}
	shardsMap, err := lindell22_trusted_dealer.Keygen(cohortConfig, crand.Reader)
	require.NoError(b, err)
	return identities, cohortConfig, shardsMap
}

func boldyreva02QuickKeygen[K bls.KeySubGroup](b *testing.B) ([]integration.IdentityKey, *integration.CohortConfig, map[helper_types.IdentityHash]*boldyreva02.Shard[K]) {
	pointInK := new(bls12381.PointG1)
	cipherSuite := &integration.CipherSuite{
		Curve: pointInK.Curve(),
		Hash:  sha256.New,
	}
	identities, err := test_utils.MakeIdentities(cipherSuite, n)
	require.NoError(b, err)
	cohortConfig := &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: hashset.NewHashSet(identities),
		Protocol: &integration.ProtocolConfig{
			Name:                 protocols.BLS,
			Threshold:            t,
			TotalParties:         n,
			SignatureAggregators: hashset.NewHashSet(identities),
		},
	}
	shardsMap, err := bls_trusted_dealer.Keygen[K](cohortConfig, crand.Reader)
	require.NoError(b, err)
	return identities, cohortConfig, shardsMap
}

func dkls232QuickKeygen(b *testing.B) ([]integration.IdentityKey, *integration.CohortConfig, []*dkls23.Shard) {
	cipherSuite := &integration.CipherSuite{
		Curve: k256.New(),
		Hash:  sha256.New,
	}
	identities, err := test_utils.MakeIdentities(cipherSuite, n)
	require.NoError(b, err)
	cohortConfig := &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: hashset.NewHashSet(identities),
		Protocol: &integration.ProtocolConfig{
			Name:                 protocols.DKLS23,
			Threshold:            t,
			TotalParties:         n,
			SignatureAggregators: hashset.NewHashSet(identities),
		},
	}

	_, _, _, shards, err := dkls23_dkg_test_utils.KeyGen(cipherSuite.Curve, cipherSuite.Hash, t, n, identities, sid)
	require.NoError(b, err)
	return identities, cohortConfig, shards
}

func lindell17QuickKeygen(b *testing.B) ([]integration.IdentityKey, *integration.CohortConfig, []*lindell17.Shard) {
	cipherSuite := &integration.CipherSuite{
		Curve: k256.New(),
		Hash:  sha256.New,
	}
	identities, err := test_utils.MakeIdentities(cipherSuite, n)
	require.NoError(b, err)
	cohortConfig := &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: hashset.NewHashSet(identities),
		Protocol: &integration.ProtocolConfig{
			Name:                 protocols.LINDELL17,
			Threshold:            t,
			TotalParties:         n,
			SignatureAggregators: hashset.NewHashSet(identities),
		},
	}
	shardsMap, err := lindell17_trusted_dealer.Keygen(cohortConfig, crand.Reader)
	require.NoError(b, err)
	shards := make([]*lindell17.Shard, n)
	for i := 0; i < n; i++ {
		shards[i] = shardsMap[identities[i].Hash()]
	}
	return identities, cohortConfig, shards
}

func BenchmarkInteractiveSigning(b *testing.B) {
	lindell17Identities, lindell17CohortConfig, lindell17Shards := lindell17QuickKeygen(b)
	lindell22Identities, lindell22CohortConfig, lindell22Shards := lindell22QuickKeygen(b)
	dkls232Identities, dkls232CohortConfig, dkls232Shards := dkls232QuickKeygen(b)
	//boldyreva02Identities, boldyreva02CohortConfig, boldyreva02Shards := boldyreva02QuickKeygen(b)
	b.Run("Lindell17", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for j := 0; j < numberOfSignatures; j++ {
				signature, err := lindell17_test_utils.DoLindell17Sign(sid, lindell17CohortConfig, lindell17Identities, lindell17Shards, 0, 1, message)
				require.NoError(b, err)
				err = ecdsa.Verify(signature, lindell17CohortConfig.CipherSuite.Hash, lindell17Shards[1].SigningKeyShare.PublicKey, message)
				require.NoError(b, err)
			}
		}
	})
	b.Run("Lindell22", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for j := 0; j < numberOfSignatures; j++ {
				transcripts := test_utils_integration.MakeTranscripts("Lindell 2022 Interactive Sign", lindell22Identities)
				participants, err := lindell22_signing_test_utils.MakeParticipants(sid, lindell22CohortConfig, lindell22Identities[:t], lindell22Shards, transcripts, false)
				require.NoError(b, err)
				partialSignatures, err := lindell22_interactive_test_utils.DoInteractiveSigning(participants, message)
				require.NoError(b, err)
				require.NotNil(b, partialSignatures)

				signature, err := signing.Aggregate(partialSignatures...)
				require.NoError(b, err)
				require.NotNil(b, signature)

				err = eddsa.Verify(lindell22CohortConfig.CipherSuite.Curve, lindell22CohortConfig.CipherSuite.Hash, signature, lindell22Shards[lindell22Identities[0].Hash()].PublicKeyShares.PublicKey, message)
				require.NoError(b, err)
			}
		}
	})
	b.Run("Dkls23", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for j := 0; j < numberOfSignatures; j++ {
				err := dkls23_test_utils.RunInteractiveSign(dkls232CohortConfig, dkls232Identities[:t], dkls232Shards[:t], message)
				require.NoError(b, err)
			}
		}
	})
}

func BenchmarkNoncePregen(b *testing.B) {
	lindell17CipherSuite := &integration.CipherSuite{
		Curve: k256.New(),
		Hash:  h,
	}
	lindell17Identities, err := test_utils.MakeIdentities(lindell17CipherSuite, n)
	require.NoError(b, err)
	lindell17CohortConfig := &integration.CohortConfig{
		CipherSuite:  lindell17CipherSuite,
		Participants: hashset.NewHashSet(lindell17Identities),
		Protocol: &integration.ProtocolConfig{
			Name:                 protocols.LINDELL17,
			Threshold:            t,
			TotalParties:         n,
			SignatureAggregators: hashset.NewHashSet(lindell17Identities),
		},
	}
	transcripts := test_utils_integration.MakeTranscripts("test", lindell17Identities)
	b.Run("Lindell17", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			participants, err := noninteractive_signing_lindell17_test_utils.MakePreGenParticipants(tau, lindell17Identities, sid, lindell17CohortConfig, transcripts)
			require.NoError(b, err)
			_, err = noninteractive_signing_lindell17_test_utils.DoLindell2017PreGen(participants)
			require.NoError(b, err)
		}
	})

	lindell22CipherSuite := &integration.CipherSuite{
		Curve: edwards25519.New(),
		Hash:  h,
	}
	lindell22Identities, err := test_utils.MakeIdentities(lindell17CipherSuite, n)
	require.NoError(b, err)
	lindell22CohortConfig, err := test_utils_integration.MakeCohortProtocol(lindell22CipherSuite, protocols.LINDELL22, lindell22Identities, t, lindell22Identities)
	require.NoError(b, err)

	b.Run("Lindell22", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			participants, err := noninteractive_signing_lindell22_test_utils.MakePreGenParticipants(tau, lindell22Identities, sid, lindell22CohortConfig, transcripts)
			require.NoError(b, err)
			_, err = noninteractive_signing_lindell22_test_utils.DoLindell2022PreGen(participants)
			require.NoError(b, err)
		}
	})
}

func BenchmarkNonInteractiveSigning(b *testing.B) {
	lindell17Identities, lindell17CohortConfig, lindell17Shards := lindell17QuickKeygen(b)
	transcripts := test_utils_integration.MakeTranscripts("test", lindell17Identities)
	lindell17Participants, err := noninteractive_signing_lindell17_test_utils.MakePreGenParticipants(1, lindell17Identities, sid, lindell17CohortConfig, transcripts)
	require.NoError(b, err)
	lindell17Batches, err := noninteractive_signing_lindell17_test_utils.DoLindell2017PreGen(lindell17Participants)
	require.NoError(b, err)

	lindell17AliceShard := lindell17Shards[0]
	lindell17Alice, err := lindell17_noninteractive_signing.NewCosigner(lindell17CohortConfig, lindell17Identities[0], lindell17AliceShard, lindell17Batches[0], 0, lindell17Identities[1], sid, nil, crand.Reader)
	require.NoError(b, err)

	lindell17BobShard := lindell17Shards[1]
	lindell17Bob, err := lindell17_noninteractive_signing.NewCosigner(lindell17CohortConfig, lindell17Identities[1], lindell17BobShard, lindell17Batches[1], 0, lindell17Identities[0], sid, nil, crand.Reader)
	require.NoError(b, err)

	b.Run("Lindell17", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for j := 0; j < numberOfSignatures; j++ {
				partialSignature, err := lindell17Alice.ProducePartialSignature(message)
				require.NoError(b, err)

				_, err = lindell17Bob.ProduceSignature(partialSignature, message)
				require.NoError(b, err)
			}
		}
	})

	lindell22Identities, lindell22CohortConfig, lindell22Shards := lindell22QuickKeygen(b)
	lindell22Participants, err := noninteractive_signing_lindell22_test_utils.MakePreGenParticipants(1, lindell22Identities, sid, lindell22CohortConfig, transcripts)
	require.NoError(b, err)
	lindell22Batches, err := noninteractive_signing_lindell22_test_utils.DoLindell2022PreGen(lindell22Participants)
	require.NoError(b, err)
	b.Run("Lindell22", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for j := 0; j < numberOfSignatures; j++ {
				partialSignatures := make([]*lindell22.PartialSignature, t)

				cosignerA, err := lindell22_noninteractive_signing.NewCosigner(lindell22Identities[0], lindell22Shards[lindell22Identities[0].Hash()], lindell22CohortConfig, hashset.NewHashSet(lindell22Identities[:t]), 0, lindell22Batches[0], sid, false, nil, crand.Reader)
				require.NoError(b, err)
				partialSignatures[0], err = cosignerA.ProducePartialSignature(message)
				require.NoError(b, err)

				cosignerB, err := lindell22_noninteractive_signing.NewCosigner(lindell22Identities[1], lindell22Shards[lindell22Identities[1].Hash()], lindell22CohortConfig, hashset.NewHashSet(lindell22Identities[:t]), 0, lindell22Batches[1], sid, false, nil, crand.Reader)
				require.NoError(b, err)
				partialSignatures[1], err = cosignerB.ProducePartialSignature(message)
				require.NoError(b, err)

				signature, err := signing.Aggregate(partialSignatures...)
				require.NoError(b, err)

				err = eddsa.Verify(lindell22CohortConfig.CipherSuite.Curve, lindell22CohortConfig.CipherSuite.Hash, signature, lindell22Shards[lindell22Identities[0].Hash()].PublicKeyShares.PublicKey, message)
				require.NoError(b, err)
			}
		}
	})

	boldyreva02Identities, boldyreva02CohortConfig, boldyreva02Shards := boldyreva02QuickKeygen[G1](b)
	b.Run("Boldyreva02", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for j := 0; j < numberOfSignatures; j++ {
				participants, err := boldyreva02_test_utils.MakeSigningParticipants[G1, G2](sid, boldyreva02CohortConfig, boldyreva02Identities, boldyreva02Shards)
				require.NoError(b, err)

				partialSignatures, err := boldyreva02_test_utils.ProducePartialSignature(participants, message)
				require.NoError(b, err)

				aggregatorInput := boldyreva02_test_utils.MapPartialSignatures(boldyreva02Identities, partialSignatures)

				agg, err := aggregation.NewAggregator[G1, G2](boldyreva02Shards[boldyreva02Identities[0].Hash()].PublicKeyShares, boldyreva02CohortConfig)
				require.NoError(b, err)

				signature, err := agg.Aggregate(aggregatorInput, message)
				require.NoError(b, err)

				err = bls.Verify(boldyreva02Shards[boldyreva02Identities[0].Hash()].PublicKeyShares.PublicKey, signature, message, nil, bls.Basic)
				require.Error(b, err)
			}
		}
	})

	b.Run("Boldyreva02 with aggregate verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			pubkeys := make([]*bls.PublicKey[G1], numberOfSignatures)
			messages := make([][]byte, numberOfSignatures)
			signatures := make([]*bls.Signature[G2], numberOfSignatures)
			for j := 0; j < numberOfSignatures; j++ {
				participants, err := boldyreva02_test_utils.MakeSigningParticipants[G1, G2](sid, boldyreva02CohortConfig, boldyreva02Identities, boldyreva02Shards)
				require.NoError(b, err)

				partialSignatures, err := boldyreva02_test_utils.ProducePartialSignature(participants, message)
				require.NoError(b, err)

				aggregatorInput := boldyreva02_test_utils.MapPartialSignatures(boldyreva02Identities, partialSignatures)

				agg, err := aggregation.NewAggregator[G1, G2](boldyreva02Shards[boldyreva02Identities[0].Hash()].PublicKeyShares, boldyreva02CohortConfig)
				require.NoError(b, err)

				signature, err := agg.Aggregate(aggregatorInput, message)
				require.NoError(b, err)

				pubkeys[j] = boldyreva02Shards[boldyreva02Identities[0].Hash()].PublicKeyShares.PublicKey
				messages[j] = message
				signatures[j] = signature
			}

			sigAg, err := bls.AggregateSignatures(signatures...)
			require.NoError(b, err)
			err = bls.AggregateVerify[G1, G2](pubkeys, messages, sigAg, nil, bls.Basic)
			require.Error(b, err)
		}
	})
}
