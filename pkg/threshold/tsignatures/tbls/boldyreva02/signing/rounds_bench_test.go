package signing_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/keygen/trusted_dealer"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/signing/aggregation"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/testutils"
)

func benchmarkCombineHelper[K bls.KeySubGroup, S bls.SignatureSubGroup](b *testing.B, threshold, n int) error {
	b.Helper()

	hashFunc := sha256.New
	message := []byte("messi > ronaldo")
	sid := []byte("sessionId")

	keysSubGroup := bls12381.GetSourceSubGroup[K]()

	cipherSuite := &integration.CipherSuite{
		Curve: keysSubGroup,
		Hash:  hashFunc,
	}

	identities, err := integration_testutils.MakeTestIdentities(cipherSuite, n)
	if err != nil {
		return err
	}

	cohort, err := integration_testutils.MakeCohortProtocol(cipherSuite, protocols.BLS, identities, threshold, identities)
	if err != nil {
		return err
	}

	shards, err := trusted_dealer.Keygen[K](cohort, crand.Reader)
	if err != nil {
		return err
	}

	publicKeyShares := shards[identities[0].Hash()].PublicKeyShares
	publicKey := publicKeyShares.PublicKey

	participants, err := testutils.MakeSigningParticipants[K, S](sid, cohort, identities, shards, bls.Basic)
	if err != nil {
		return err
	}

	partialSignatures, err := testutils.ProducePartialSignature(participants, message, bls.Basic)
	if err != nil {
		return err
	}

	aggregatorInput := testutils.MapPartialSignatures(identities, partialSignatures)

	agg, err := aggregation.NewAggregator[K, S](shards[identities[0].Hash()].PublicKeyShares, bls.Basic, cohort)
	if err != nil {
		return err
	}

	b.StartTimer()
	signature, _, err := agg.Aggregate(aggregatorInput, message, bls.Basic)
	if err != nil {
		return err
	}
	b.StopTimer()

	err = bls.Verify(publicKey, signature, message, nil, bls.Basic, nil)
	if err != nil {
		return err
	}
	return nil
}

func Benchmark_Basic(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode.")
	}

	threshold := 5
	total := 7

	b.Run("short keys", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			err := testutils.SigningRoundTrip[bls12381.G1, bls12381.G2](threshold, total, bls.Basic)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("short signatures", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			err := testutils.SigningRoundTrip[bls12381.G2, bls12381.G1](threshold, total, bls.Basic)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func Benchmark_Combine(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode.")
	}

	threshold := 5
	total := 7

	b.Run("short keys", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			err := benchmarkCombineHelper[bls12381.G1, bls12381.G2](b, threshold, total)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("short signatures", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			err := benchmarkCombineHelper[bls12381.G2, bls12381.G1](b, threshold, total)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
