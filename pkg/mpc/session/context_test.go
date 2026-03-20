package session_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/zero/przs"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

func Test_ContextSessionId(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	quorum := sharing.NewOrdinalShareholderSet(4)
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)

	sids := make(map[sharing.ID]network.SID)
	for id, ctx := range ctxs {
		sids[id] = ctx.SessionID()
	}
	sid := sids[sharing.ID(1)]
	for _, s := range sids {
		require.Equal(t, sid, s)
	}
}

func Test_ContextTranscript(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	quorum := sharing.NewOrdinalShareholderSet(4)
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)

	tapes := make(map[sharing.ID][]byte)
	for id, ctx := range ctxs {
		var err error
		tapes[id], err = ctx.Transcript().ExtractBytes("test1", 32)
		require.NoError(t, err)
	}
	tape := tapes[sharing.ID(1)]
	for _, ts := range tapes {
		require.Equal(t, tape, ts)
	}

	for id, ctx := range ctxs {
		var err error
		tapes[id], err = ctx.Transcript().ExtractBytes("test2", 64)
		require.NoError(t, err)
	}
	tape = tapes[sharing.ID(1)]
	for _, ts := range tapes {
		require.Equal(t, tape, ts)
	}
}

func Test_SubContextTranscriptAndZeroShare(t *testing.T) {
	t.Parallel()
	prng := pcg.New(303, 404)
	curve := k256.NewCurve()

	quorum := sharing.NewOrdinalShareholderSet(4)
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)

	subQuorum := hashset.NewComparable[sharing.ID](1, 2, 3).Freeze()
	subCtxs := make(map[sharing.ID]*session.Context)
	for id := range subQuorum.Iter() {
		subCtx, err := ctxs[id].SubContext(subQuorum)
		require.NoError(t, err)
		subCtxs[id] = subCtx
	}

	sum := curve.OpIdentity()
	for id := range subQuorum.Iter() {
		share, err := przs.SampleZeroShare(subCtxs[id], curve)
		require.NoError(t, err)
		sum = sum.Op(share.Value())
	}
	require.True(t, sum.IsOpIdentity())

	baseChallenge, err := ctxs[sharing.ID(1)].Transcript().ExtractBytes("challenge", 32)
	require.NoError(t, err)
	subChallenge, err := subCtxs[sharing.ID(1)].Transcript().ExtractBytes("challenge", 32)
	require.NoError(t, err)
	require.NotEqual(t, baseChallenge, subChallenge)
}
