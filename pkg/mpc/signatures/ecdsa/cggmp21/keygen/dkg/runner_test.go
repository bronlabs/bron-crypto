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
		refPaillier := shards[ids[0]].AuxInfo().PaillierPublicKeys()
		refPedersen := shards[ids[0]].AuxInfo().RingPedersenPublicKeys()
		for _, id := range ids {
			pail := shards[id].AuxInfo().PaillierPublicKeys()
			ped := shards[id].AuxInfo().RingPedersenPublicKeys()
			require.Len(t, pail, len(ids))
			require.Len(t, ped, len(ids))
			for _, k := range ids {
				require.True(t, refPaillier[k].Equal(pail[k]))
				require.True(t, refPedersen[k].Equal(ped[k]))
			}
			// the local secret material must match the agreed-upon public keys
			require.True(t, shards[id].AuxInfo().PaillierSecretKey().Public().Equal(pail[id]))
			require.True(t, shards[id].AuxInfo().RingPedersenSecretKey().Export().Equal(ped[id]))
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
