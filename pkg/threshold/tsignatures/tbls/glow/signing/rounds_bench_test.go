package signing_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	ttu "github.com/bronlabs/krypton-primitives/pkg/base/types/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/bls"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tbls/glow/keygen/trusted_dealer"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tbls/glow/signing"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tbls/glow/testutils"
)

func benchmarkCombineHelper(b *testing.B, threshold, n int) error {
	b.Helper()
	hashFunc := sha256.New
	message := []byte("messi > ronaldo")
	sid := []byte("sessionId")

	cipherSuite, err := ttu.MakeSigningSuite(bls12381.NewG2(), hashFunc)
	if err != nil {
		return err
	}

	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	if err != nil {
		return err
	}

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, threshold, identities)
	if err != nil {
		return err
	}

	shards, err := trusted_dealer.Keygen(protocol, crand.Reader)
	if err != nil {
		return err
	}

	thisShard, exists := shards.Get(identities[0])
	if !exists {
		return errs.NewMissing("shard for identities[0]")
	}
	publicKeyShares := thisShard.PublicKeyShares
	publicKey := publicKeyShares.PublicKey

	participants, err := testutils.MakeSigningParticipants(sid, protocol, identities, shards)
	if err != nil {
		return err
	}

	partialSignatures, err := testutils.ProducePartialSignature(participants, message)
	if err != nil {
		return err
	}

	aggregatorInput := testutils.MapPartialSignatures(b, identities, partialSignatures)

	b.StartTimer()
	signature, err := signing.Aggregate(publicKeyShares, protocol, aggregatorInput, message)
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
		err := testutils.DoSignRoundTrip(b, threshold, total)
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
