package dkg_test

import (
	"bytes"
	"encoding/hex"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro"
	gennaroTU "github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/dkls23/keygen/dkg"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func TestRunner_HappyPath(t *testing.T) {
	t.Parallel()

	const (
		threshold = uint(2)
		total     = 3
	)

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()
	sessionID := ntu.MakeRandomSessionID(t, prng)
	accessStructure, err := sharing.NewThresholdAccessStructure(threshold, hashset.NewComparable[sharing.ID](1, 2, 3).Freeze())
	require.NoError(t, err)

	tape := hagrid.NewTranscript(hex.EncodeToString(sessionID[:]))
	tapesMap := make(map[sharing.ID]transcripts.Transcript)

	ids := slices.Collect(accessStructure.Shareholders().Iter())
	gennaroParticipants := make([]*gennaro.Participant[*k256.Point, *k256.Scalar], accessStructure.Shareholders().Size())
	for i, id := range ids {
		tapesMap[id] = tape.Clone()
		gennaroParticipants[i], err = gennaro.NewParticipant(sessionID, curve, id, accessStructure, fiatshamir.Name, tapesMap[id], prng)
		require.NoError(t, err)
	}
	dkgOutputs, err := gennaroTU.DoGennaroDKG(t, gennaroParticipants)
	require.NoError(t, err)

	runners := make(map[sharing.ID]network.Runner[*dkls23.Shard[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]])
	for id := range accessStructure.Shareholders().Iter() {
		dkgOutput, ok := dkgOutputs.Get(id)
		require.True(t, ok)
		baseShard, err := tecdsa.NewShard(dkgOutput.Share(), dkgOutput.VerificationVector(), accessStructure)
		require.NoError(t, err)
		tapesMap[id] = tape.Clone()

		runner, err := dkg.NewRunner(sessionID, id, baseShard, tapesMap[id], pcg.NewRandomised())
		require.NoError(t, err)
		runners[id] = runner
	}

	shards := ntu.TestExecuteRunners(t, runners)
	require.Len(t, shards, total)

	publicKeys := make([]*k256.Point, 0, total)
	for _, shard := range shards {
		publicKeys = append(publicKeys, shard.PublicKey().Value())
	}
	for i := 1; i < len(publicKeys); i++ {
		require.True(t, publicKeys[0].Equal(publicKeys[i]))
	}

	for th := accessStructure.Threshold(); th <= uint(accessStructure.Shareholders().Size()); th++ {
		for shardsSubset := range sliceutils.Combinations(slices.Collect(maps.Values(shards)), th) {
			feldmanScheme, err := feldman.NewScheme(curve.Generator(), accessStructure.Threshold(), accessStructure.Shareholders())
			require.NoError(t, err)
			sharesSubset := sliceutils.Map(shardsSubset, func(s *dkls23.Shard[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]) *feldman.Share[*k256.Scalar] {
				return s.Share()
			})
			recoveredSk, err := feldmanScheme.Reconstruct(sharesSubset...)
			require.NoError(t, err)
			recoveredPk := curve.ScalarBaseMul(recoveredSk.Value())
			require.True(t, recoveredPk.Equal(publicKeys[0]))
		}
	}

	transcriptValues := make([][]byte, 0, len(tapesMap))
	for _, tr := range tapesMap {
		v, err := tr.ExtractBytes("test", 32)
		require.NoError(t, err)
		transcriptValues = append(transcriptValues, v)
	}
	for i := 1; i < len(transcriptValues); i++ {
		require.True(t, bytes.Equal(transcriptValues[i-1], transcriptValues[i]))
	}
}
