package signing_test

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa/lindell17/keygen/trusted_dealer"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa/lindell17/signing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
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

	ctxs := session_testutils.MakeRandomContexts(t, hashset.NewComparable(primaryID, secondaryID).Freeze(), prng)
	message := []byte("hello from lindell17 runner")

	primaryRunner, err := signing.NewPrimaryRunner(
		ctxs[primaryID],
		suite,
		secondaryID,
		primaryShard,
		fiatshamir.Name,
		pcg.NewRandomised(),
		message,
	)
	require.NoError(t, err)

	secondaryRunner, err := signing.NewSecondaryRunner(
		ctxs[secondaryID],
		suite,
		primaryID,
		secondaryShard,
		fiatshamir.Name,
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

	primaryTapeCheck, err := ctxs[primaryID].Transcript().ExtractBytes("test", 32)
	require.NoError(t, err)
	secondaryTapeCheck, err := ctxs[secondaryID].Transcript().ExtractBytes("test", 32)
	require.NoError(t, err)
	require.True(t, bytes.Equal(primaryTapeCheck, secondaryTapeCheck))
}
