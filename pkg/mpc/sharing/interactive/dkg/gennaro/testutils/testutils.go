package testutils

import (
	"maps"
	"slices"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/interactive/dkg/gennaro"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/stretchr/testify/require"
)

func MakeGennaroDKGRunners[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](tb testing.TB, ctxs map[sharing.ID]*session.Context, accessStructure *accessstructures.Threshold, niCompiler compiler.Name, group algebra.PrimeGroup[G, S]) map[sharing.ID]network.Runner[*gennaro.DKGOutput[G, S]] {
	tb.Helper()

	runners := make(map[sharing.ID]network.Runner[*gennaro.DKGOutput[G, S]])
	for id := range accessStructure.Shareholders().Iter() {
		runner, err := gennaro.NewGennaroDKGRunner(ctxs[id], group, accessStructure, niCompiler, pcg.NewRandomised())
		require.NoError(tb, err)
		runners[id] = runner
	}

	return runners
}

func DoGennaroRound1[E gennaro.GroupElement[E, S], S gennaro.Scalar[S]](tb testing.TB, participants map[sharing.ID]*gennaro.Participant[E, S]) map[sharing.ID]*gennaro.Round1Broadcast[E, S] {
	tb.Helper()
	r1bo := make(map[sharing.ID]*gennaro.Round1Broadcast[E, S])
	for id, p := range participants {
		var err error
		r1bo[id], err = p.Round1()
		require.NoError(tb, err)
	}
	return r1bo
}

func DoGennaroRound2[E gennaro.GroupElement[E, S], S gennaro.Scalar[S]](tb testing.TB, participants map[sharing.ID]*gennaro.Participant[E, S], r2bi map[sharing.ID]network.RoundMessages[*gennaro.Round1Broadcast[E, S]]) (r2bo map[sharing.ID]*gennaro.Round2Broadcast[E, S], r2uo map[sharing.ID]network.RoundMessages[*gennaro.Round2Unicast[E, S]]) {
	tb.Helper()
	r2bo = make(map[sharing.ID]*gennaro.Round2Broadcast[E, S], len(participants))
	r2uo = make(map[sharing.ID]network.RoundMessages[*gennaro.Round2Unicast[E, S]], len(participants))
	for id, p := range participants {
		var err error
		r2bo[id], r2uo[id], err = p.Round2(r2bi[id])
		require.NoError(tb, err)
	}
	return r2bo, r2uo
}

func DoGennaroRound3[E gennaro.GroupElement[E, S], S gennaro.Scalar[S]](tb testing.TB, participants map[sharing.ID]*gennaro.Participant[E, S], r3bi map[sharing.ID]network.RoundMessages[*gennaro.Round2Broadcast[E, S]], r3ui map[sharing.ID]network.RoundMessages[*gennaro.Round2Unicast[E, S]]) map[sharing.ID]*gennaro.DKGOutput[E, S] {
	tb.Helper()
	dkgOutput := make(map[sharing.ID]*gennaro.DKGOutput[E, S])
	for id, p := range participants {
		v, err := p.Round3(r3bi[id], r3ui[id])
		require.NoError(tb, err)
		dkgOutput[id] = v
	}
	return dkgOutput
}

func DoGennaroDKG[E gennaro.GroupElement[E, S], S gennaro.Scalar[S]](tb testing.TB, participants map[sharing.ID]*gennaro.Participant[E, S]) map[sharing.ID]*gennaro.DKGOutput[E, S] {
	tb.Helper()
	r1bo := DoGennaroRound1(tb, participants)
	r2bi := ntu.MapBroadcastO2I(tb, slices.Collect(maps.Values(participants)), r1bo)
	r2bo, r2uo := DoGennaroRound2(tb, participants, r2bi)
	r3bi, r3ui := ntu.MapO2I(tb, slices.Collect(maps.Values(participants)), r2bo, r2uo)
	dkgOutput := DoGennaroRound3(tb, participants, r3bi, r3ui)
	return dkgOutput
}
