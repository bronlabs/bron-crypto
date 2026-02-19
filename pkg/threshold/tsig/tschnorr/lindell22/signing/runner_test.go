package signing_test

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/bip340"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr/lindell22"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr/lindell22/signing"
	ltu "github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr/lindell22/testutils"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func TestRunnerHappyPath_BIP340(t *testing.T) {
	t.Parallel()

	const (
		threshold = uint(2)
		total     = uint(3)
	)

	prng := pcg.NewRandomised()
	group := k256.NewCurve()
	sid := ntu.MakeRandomSessionID(t, prng)
	dkgTape := hagrid.NewTranscript("TestLindell22SigningRunnerDKG")

	scheme, err := bip340.NewScheme(prng)
	require.NoError(t, err)

	shareholders := sharing.NewOrdinalShareholderSet(total)
	accessStructure, err := sharing.NewThresholdAccessStructure(threshold, shareholders)
	require.NoError(t, err)

	parties := make([]*gennaro.Participant[*k256.Point, *k256.Scalar], 0, total)
	for id := range shareholders.Iter() {
		party, err := gennaro.NewParticipant(sid, group, id, accessStructure, fiatshamir.Name, dkgTape.Clone(), pcg.NewRandomised())
		require.NoError(t, err)
		parties = append(parties, party)
	}

	shards, err := ltu.DoLindell22DKG(t, parties)
	require.NoError(t, err)
	require.Equal(t, int(total), shards.Size())

	signingSID := ntu.MakeRandomSessionID(t, prng)
	quorum := shareholders
	message := []byte("Hello from Lindell22 runner")
	variant := scheme.Variant()

	tapes := make(map[sharing.ID]transcripts.Transcript, total)
	runners := make(map[sharing.ID]network.Runner[*lindell22.PartialSignature[*k256.Point, *k256.Scalar]], total)
	for id := range quorum.Iter() {
		shard, ok := shards.Get(id)
		require.True(t, ok)

		tapes[id] = hagrid.NewTranscript("TestLindell22SigningRunner")
		runner, err := signing.NewRunner(
			signingSID,
			shard,
			quorum,
			group,
			fiatshamir.Name,
			variant,
			message,
			pcg.NewRandomised(),
			tapes[id],
		)
		require.NoError(t, err)
		runners[id] = runner
	}

	partialSignatures := ntu.TestExecuteRunners(t, runners)
	require.Len(t, partialSignatures, int(quorum.Size()))

	anyID := quorum.List()[0]
	publicMaterial, ok := shards.Get(anyID)
	require.True(t, ok)

	aggregator, err := signing.NewAggregator(publicMaterial.PublicKeyMaterial(), scheme)
	require.NoError(t, err)

	sig, err := aggregator.Aggregate(hashmap.NewComparableFromNativeLike(partialSignatures).Freeze(), message)
	require.NoError(t, err)
	require.NotNil(t, sig)

	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	err = verifier.Verify(sig, publicMaterial.PublicKey(), message)
	require.NoError(t, err)

	firstTapeBytes, err := tapes[anyID].ExtractBytes("test", 32)
	require.NoError(t, err)
	for id := range quorum.Iter() {
		if id == anyID {
			continue
		}
		b, err := tapes[id].ExtractBytes("test", 32)
		require.NoError(t, err)
		require.True(t, slices.Equal(firstTapeBytes, b))
	}
}
