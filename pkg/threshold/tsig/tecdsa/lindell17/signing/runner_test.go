package signing_test

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/lindell17/keygen/trusted_dealer"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/lindell17/signing"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func TestRunnerHappyPath_K256_2P(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()
	suite, err := ecdsa.NewSuite(curve, crypto.SHA256.New)
	require.NoError(t, err)

	shareholders := sharing.NewOrdinalShareholderSet(3)
	shards, publicKey, err := trusted_dealer.DealRandom(curve, shareholders, 1024, prng)
	require.NoError(t, err)

	primaryID := sharing.ID(1)
	secondaryID := sharing.ID(2)
	primaryShard, ok := shards.Get(primaryID)
	require.True(t, ok)
	secondaryShard, ok := shards.Get(secondaryID)
	require.True(t, ok)

	sessionID := ntu.MakeRandomSessionID(t, prng)
	primaryTape := hagrid.NewTranscript("test")
	secondaryTape := primaryTape.Clone()
	message := []byte("hello from lindell17 runner")

	primaryRunner, err := signing.NewPrimaryRunner(
		sessionID,
		suite,
		secondaryID,
		primaryShard,
		fiatshamir.Name,
		primaryTape,
		pcg.NewRandomised(),
		message,
	)
	require.NoError(t, err)

	secondaryRunner, err := signing.NewSecondaryRunner(
		sessionID,
		suite,
		primaryID,
		secondaryShard,
		fiatshamir.Name,
		secondaryTape,
		pcg.NewRandomised(),
		message,
	)
	require.NoError(t, err)

	runners := map[sharing.ID]network.Runner[*ecdsa.Signature[*k256.Scalar]]{
		primaryID:   primaryRunner,
		secondaryID: secondaryRunner,
	}
	outputs := ntu.TestExecuteRunners(t, runners)
	require.Len(t, outputs, 2)

	signature, ok := outputs[primaryID]
	require.True(t, ok)
	require.NotNil(t, signature)

	secondaryOut, ok := outputs[secondaryID]
	require.True(t, ok)
	require.Nil(t, secondaryOut)

	verifier, err := ecdsa.NewVerifier(suite)
	require.NoError(t, err)
	err = verifier.Verify(signature, publicKey, message)
	require.NoError(t, err)

	primaryTapeCheck, err := primaryTape.ExtractBytes("test", 32)
	require.NoError(t, err)
	secondaryTapeCheck, err := secondaryTape.ExtractBytes("test", 32)
	require.NoError(t, err)
	require.True(t, bytes.Equal(primaryTapeCheck, secondaryTapeCheck))
}
