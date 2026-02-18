package session_test

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/session"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	quorum := sharing.NewOrdinalShareholderSet(4)
	participants := make([]*session.Participant, 4)

	for i := range 4 {
		p, err := session.NewParticipant(sharing.ID(i+1), quorum, prng)
		require.NoError(t, err)
		participants[i] = p
	}

	r1bo := make(map[sharing.ID]*session.Round1Broadcast)
	for _, p := range participants {
		var err error
		r1bo[p.SharingID()], err = p.Round1()
		require.NoError(t, err)
	}

	r2bi := ntu.MapBroadcastO2I(t, participants, r1bo)
	r2uo := make(map[sharing.ID]network.RoundMessages[*session.Round2P2P])
	for _, p := range participants {
		var err error
		r2uo[p.SharingID()], err = p.Round2(r2bi[p.SharingID()])
		require.NoError(t, err)
	}

	r3ui := ntu.MapUnicastO2I(t, participants, r2uo)
	r3uo := make(map[sharing.ID]network.RoundMessages[*session.Round3P2P])
	for _, p := range participants {
		var err error
		r3uo[p.SharingID()], err = p.Round3(r3ui[p.SharingID()])
		require.NoError(t, err)
	}

	r4ui := ntu.MapUnicastO2I(t, participants, r3uo)
	ctxs := make(map[sharing.ID]*session.Context)
	for _, p := range participants {
		var err error
		ctxs[p.SharingID()], err = p.Round4(r4ui[p.SharingID()])
		require.NoError(t, err)
	}

	t.Run("should agree on session id", func(t *testing.T) {
		t.Parallel()
		sid := ctxs[participants[0].SharingID()].SessionID()
		for _, p := range participants[1:] {
			require.Equal(t, sid, ctxs[p.SharingID()].SessionID())
		}
	})

	t.Run("should agree on transcript", func(t *testing.T) {
		t.Parallel()
		var values [][]byte
		for _, p := range participants {
			value, err := ctxs[p.SharingID()].Transcript().ExtractBytes("challenge", 32)
			require.NoError(t, err)
			values = append(values, value)
		}
		for i := 1; i < len(values); i++ {
			require.True(t, slices.Equal(values[i-1], values[i]))
		}
	})

	t.Run("should sum zero shares to identity", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		sum := curve.OpIdentity()
		for _, p := range participants {
			share, err := session.SampleZeroShare(ctxs[p.SharingID()], curve)
			require.NoError(t, err)
			sum = sum.Op(share.Value())
		}
		require.True(t, sum.IsOpIdentity())
	})
}
