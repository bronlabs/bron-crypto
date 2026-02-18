package dkg_test

import (
	"encoding/hex"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/lindell17"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/lindell17/keygen/dkg"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func TestRunnerHappyPath_K256_2of3(t *testing.T) {
	t.Parallel()

	const (
		threshold      = uint(2)
		total          = 3
		paillierKeyLen = 1024
	)

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()
	sessionID := ntu.MakeRandomSessionID(t, prng)
	tape := hagrid.NewTranscript(hex.EncodeToString(sessionID[:]))

	shareholders := hashset.NewComparable[sharing.ID](1, 2, 3).Freeze()
	accessStructure, err := sharing.NewThresholdAccessStructure(threshold, shareholders)
	require.NoError(t, err)

	feldmanScheme, err := feldman.NewScheme(curve.Generator(), accessStructure.Threshold(), accessStructure.Shareholders())
	require.NoError(t, err)
	feldmanOutput, _, err := feldmanScheme.DealRandom(prng)
	require.NoError(t, err)

	runners := make(map[sharing.ID]network.Runner[*lindell17.Shard[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]])
	tapes := make(map[sharing.ID]transcripts.Transcript)
	for id, share := range feldmanOutput.Shares().Iter() {
		baseShard, err := tecdsa.NewShard(share, feldmanOutput.VerificationMaterial(), accessStructure)
		require.NoError(t, err)
		tapes[id] = tape.Clone()

		runner, err := dkg.NewRunner(
			sessionID,
			baseShard,
			paillierKeyLen,
			curve,
			pcg.NewRandomised(),
			fiatshamir.Name,
			tapes[id],
		)
		require.NoError(t, err)
		runners[id] = runner
	}

	outputs := ntu.TestExecuteRunners(t, runners)
	require.Len(t, outputs, total)

	publicKeys := make([]*k256.Point, 0, total)
	for id, shard := range outputs {
		require.NotNil(t, shard.PaillierPrivateKey(), "Shard %d should have Paillier private key", id)
		require.NotNil(t, shard.PaillierPublicKeys(), "Shard %d should have Paillier public keys", id)
		require.NotNil(t, shard.EncryptedShares(), "Shard %d should have encrypted shares", id)
		require.Equal(t, total-1, shard.PaillierPublicKeys().Size(), "Shard %d should have paillier public keys from all other parties", id)
		require.Equal(t, total-1, shard.EncryptedShares().Size(), "Shard %d should have encrypted shares from all other parties", id)
		publicKeys = append(publicKeys, shard.PublicKey().Value())
	}

	for i := 1; i < len(publicKeys); i++ {
		require.True(t, publicKeys[0].Equal(publicKeys[i]), "all participants should derive the same public key")
	}

	feldmanShares := make([]*feldman.Share[*k256.Scalar], 0, len(outputs))
	for _, shard := range outputs {
		feldmanShares = append(feldmanShares, shard.Share())
	}
	recovered, err := feldmanScheme.Reconstruct(feldmanShares...)
	require.NoError(t, err)
	recoveredPk := curve.ScalarBaseMul(recovered.Value())
	require.True(t, recoveredPk.Equal(publicKeys[0]))

	// For threshold-sized subsets, reconstruction must yield the same public key.
	ids := slices.Collect(maps.Keys(outputs))
	for i := range ids {
		for j := i + 1; j < len(ids); j++ {
			subsetShares := []*feldman.Share[*k256.Scalar]{
				outputs[ids[i]].Share(),
				outputs[ids[j]].Share(),
			}
			rec, err := feldmanScheme.Reconstruct(subsetShares...)
			require.NoError(t, err)
			require.True(t, curve.ScalarBaseMul(rec.Value()).Equal(publicKeys[0]))
		}
	}

	firstTapeBytes, err := tapes[ids[0]].ExtractBytes("test", 32)
	require.NoError(t, err)
	for _, id := range ids[1:] {
		b, err := tapes[id].ExtractBytes("test", 32)
		require.NoError(t, err)
		require.True(t, slices.Equal(firstTapeBytes, b))
	}
}
