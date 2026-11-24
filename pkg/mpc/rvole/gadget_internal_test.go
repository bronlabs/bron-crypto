package rvole

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// TestGadgetDependsOnSessionOnly checks the Variant III premise that g is fixed
// before any message is exchanged: it must not change with the state of the
// session transcript, which the OTs advance before the core is built, and it
// must agree between the two parties of a session and differ across sessions.
func TestGadgetDependsOnSessionOnly(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	suite, err := NewSuite(2, k256.NewCurve())
	require.NoError(t, err)
	quorum := hashset.NewComparable(sharing.ID(1), sharing.ID(2)).Freeze()
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)

	first, err := newParticipant(ctxs[1], suite, prng)
	require.NoError(t, err)
	ctxs[1].Transcript().AppendBytes("BRON_CRYPTO-TEST-OT-MESSAGE-", []byte("whatever the counterparty sends"))
	second, err := newParticipant(ctxs[1], suite, prng)
	require.NoError(t, err)
	other, err := newParticipant(ctxs[2], suite, prng)
	require.NoError(t, err)
	require.Len(t, first.g, suite.xi)
	for j := range first.g {
		require.True(t, first.g[j].Equal(second.g[j]), "g_%d changed with the transcript", j)
		require.True(t, first.g[j].Equal(other.g[j]), "g_%d differs between the parties", j)
	}

	foreign := session_testutils.MakeRandomContexts(t, quorum, prng)
	third, err := newParticipant(foreign[1], suite, prng)
	require.NoError(t, err)
	require.False(t, first.g[0].Equal(third.g[0]), "g does not depend on the session")
}
