package dkg_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/trusteddealer"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21/keygen/dkg"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
)

// TestHappyPathRunner runs the aux-info DKG end-to-end through the network
// runner (over the in-memory router) and checks the shards, transcripts, and
// round-completion notifications are consistent across all parties.
func TestHappyPathRunner(t *testing.T) {
	t.Parallel()

	type shard = *cggmp21.Shard[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]

	group := k256.NewCurve()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	accessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	prng := pcg.NewRandomised()
	quorum := accessStructure.Shareholders()
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)
	dealt, err := trusteddealer.Deal(group, accessStructure, prng)
	require.NoError(t, err)

	runners := make(map[sharing.ID]network.Runner[shard])
	for id := range quorum.Iter() {
		bs, ok := dealt.Get(id)
		require.True(t, ok)
		runners[id], err = dkg.NewRunner[*k256.Point, *k256.BaseFieldElement, *k256.Scalar](ctxs[id], bs, pcg.NewRandomised())
		require.NoError(t, err)
	}

	shards, notifications := ntu.TestExecuteRunners(t, runners)
	require.Len(t, shards, shareholders.Size())
	ids := shareholders.List()

	t.Run("public key is consistent", func(t *testing.T) {
		t.Parallel()
		ref := shards[ids[0]].PublicKeyValue()
		for _, id := range ids {
			require.NotNil(t, shards[id])
			require.True(t, ref.Equal(shards[id].PublicKeyValue()))
		}
	})

	t.Run("aux info agrees across parties", func(t *testing.T) {
		t.Parallel()
		// Each party's auxiliary info excludes its own keys, so every map covers
		// only the other len(ids)-1 shareholders.
		for _, id := range ids {
			pail := shards[id].AuxInfo().PaillierPublicKeys()
			ped := shards[id].AuxInfo().RingPedersenPublicKeys()
			require.Len(t, pail, len(ids)-1)
			require.Len(t, ped, len(ids)-1)
			_, okPail := pail[id]
			_, okPed := ped[id]
			require.False(t, okPail)
			require.False(t, okPed)
		}
		// No single party holds a complete map, so the binding invariant is that
		// party k's own secret key matches the public key every other party
		// recorded for k.
		for _, k := range ids {
			refPaillier := shards[k].AuxInfo().PaillierSecretKey().Public()
			refPedersen := shards[k].AuxInfo().RingPedersenSecretKey().Export()
			for _, id := range ids {
				if id == k {
					continue
				}
				pail, okPail := shards[id].AuxInfo().PaillierPublicKey(k)
				ped, okPed := shards[id].AuxInfo().RingPedersenPublicKey(k)
				require.True(t, okPail)
				require.True(t, okPed)
				require.True(t, refPaillier.Equal(pail))
				require.True(t, refPedersen.Equal(ped))
			}
		}
	})

	t.Run("transcripts are consistent", func(t *testing.T) {
		t.Parallel()
		var ref []byte
		for _, id := range ids {
			sample, err := ctxs[id].Transcript().ExtractBytes("test", 32)
			require.NoError(t, err)
			if ref == nil {
				ref = sample
			} else {
				require.True(t, bytes.Equal(ref, sample))
			}
		}
	})

	t.Run("notifications are consistent", func(t *testing.T) {
		t.Parallel()
		ntu.RequireRoundCompletedNotifications(t, notifications, quorum, dkg.ProtocolName, 4)
	})
}
