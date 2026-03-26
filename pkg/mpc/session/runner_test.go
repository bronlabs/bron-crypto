package session_test

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/zero/przs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
)

func TestHappyPathRunner(t *testing.T) {
	t.Parallel()

	quorum := sharing.NewOrdinalShareholderSet(5)
	runners := make(map[sharing.ID]network.Runner[*session.Context])
	for id := range quorum.Iter() {
		r, err := session.NewSessionRunner(id, quorum, pcg.NewRandomised())
		require.NoError(t, err)
		runners[id] = r
	}

	contexts := ntu.TestExecuteRunners(t, runners)
	t.Run("should agree on session id", func(t *testing.T) {
		t.Parallel()
		sid := contexts[quorum.List()[0]].SessionID()
		for _, ctx := range contexts {
			require.Equal(t, sid, ctx.SessionID())
		}
	})

	t.Run("should agree on transcript", func(t *testing.T) {
		t.Parallel()
		var values [][]byte
		for _, ctx := range contexts {
			value, err := ctx.Transcript().ExtractBytes("challenge", 32)
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
		for _, ctx := range contexts {
			share, err := przs.SampleZeroShare(ctx, curve)
			require.NoError(t, err)
			sum = sum.Op(share.Value())
		}
		require.True(t, sum.IsOpIdentity())
	})
}
