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
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow/keygen/trusted_dealer"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow/signing/aggregation"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow/testutils"
)

func benchmarkCombineHelper(b *testing.B, threshold, n int) error {
	b.Helper()
	hashFunc := sha256.New
	message := []byte("messi > ronaldo")
	sid := []byte("sessionId")

	cipherSuite := &integration.CipherSuite{
		Curve: bls12381.NewG1(),
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

	shards, err := trusted_dealer.Keygen(cohort, crand.Reader)
	if err != nil {
		return err
	}

	publicKeyShares := shards[identities[0].Hash()].PublicKeyShares
	publicKey := publicKeyShares.PublicKey

	participants, err := testutils.MakeSigningParticipants(sid, cohort, identities, shards)
	if err != nil {
		return err
	}

	partialSignatures, err := testutils.ProducePartialSignature(participants, message)
	if err != nil {
		return err
	}

	aggregatorInput := testutils.MapPartialSignatures(identities, partialSignatures)

	agg, err := aggregation.NewAggregator(sid, shards[identities[0].Hash()].PublicKeyShares, cohort)
	if err != nil {
		return err
	}

	b.StartTimer()
	signature, err := agg.Aggregate(aggregatorInput, message)
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

	for n := 0; n < b.N; n++ {
		err := testutils.SigningRoundTrip(threshold, total)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func Benchmark_Combine(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode.")
	}

	threshold := 5
	total := 7

	for n := 0; n < b.N; n++ {
		err := benchmarkCombineHelper(b, threshold, total)
		if err != nil {
			b.Fatal(err)
		}
	}
}
