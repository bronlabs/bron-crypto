package testutils

import (
	"bytes"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/maputils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/gennaro"
	gennaroTU "github.com/bronlabs/bron-crypto/pkg/mpc/dkg/gennaro/testutils"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa/dkls23/keygen/dkg"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

func RunDKLs23DKG[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](tb testing.TB, curve ecdsa.Curve[P, B, S], accessStructure *threshold.Threshold) map[sharing.ID]*dkls23.Shard[P, B, S] {
	tb.Helper()

	var err error
	prng := pcg.NewRandomised()
	ctxs := session_testutils.MakeRandomContexts(tb, accessStructure.Shareholders(), prng)
	gennaroDkgParticipants := make(map[sharing.ID]*gennaro.Participant[P, S])
	for id, ctx := range ctxs {
		p, err := gennaro.NewParticipant(ctx, curve, accessStructure, fiatshamir.Name, prng)
		require.NoError(tb, err)
		gennaroDkgParticipants[id] = p
	}
	dkgOutputs := gennaroTU.DoGennaroDKG(tb, gennaroDkgParticipants)

	dkgParticipants := make(map[sharing.ID]*dkg.Participant[P, B, S])
	for id, dkgOutput := range dkgOutputs {
		ecdsaShard, err := tecdsa.NewShard(dkgOutput.Share(), dkgOutput.VerificationVector(), accessStructure)
		require.NoError(tb, err)

		dkgParticipants[id], err = dkg.NewParticipant(ctxs[id], ecdsaShard, prng)
		require.NoError(tb, err)
	}

	r1uo := make(map[sharing.ID]network.RoundMessages[*dkg.Round1P2P[P, B, S], *dkg.Participant[P, B, S]])
	for id, party := range dkgParticipants {
		r1uo[id], err = party.Round1()
		require.NoError(tb, err)
	}

	r2ui := ntu.MapUnicastO2I(tb, slices.Collect(maps.Values(dkgParticipants)), r1uo)
	r2uo := make(map[sharing.ID]network.RoundMessages[*dkg.Round2P2P[P, B, S], *dkg.Participant[P, B, S]])
	for id, party := range dkgParticipants {
		r2uo[id], err = party.Round2(r2ui[id])
		require.NoError(tb, err)
	}

	r3ui := ntu.MapUnicastO2I(tb, slices.Collect(maps.Values(dkgParticipants)), r2uo)
	r3uo := make(map[sharing.ID]network.RoundMessages[*dkg.Round3P2P[P, B, S], *dkg.Participant[P, B, S]])
	for id, party := range dkgParticipants {
		r3uo[id], err = party.Round3(r3ui[id])
		require.NoError(tb, err)
	}

	r4ui := ntu.MapUnicastO2I(tb, slices.Collect(maps.Values(dkgParticipants)), r3uo)
	r4uo := make(map[sharing.ID]network.RoundMessages[*dkg.Round4P2P[P, B, S], *dkg.Participant[P, B, S]])
	for id, party := range dkgParticipants {
		r4uo[id], err = party.Round4(r4ui[id])
		require.NoError(tb, err)
	}

	r5ui := ntu.MapUnicastO2I(tb, slices.Collect(maps.Values(dkgParticipants)), r4uo)
	r5uo := make(map[sharing.ID]network.RoundMessages[*dkg.Round5P2P[P, B, S], *dkg.Participant[P, B, S]])
	for id, party := range dkgParticipants {
		r5uo[id], err = party.Round5(r5ui[id])
		require.NoError(tb, err)
	}

	r6ui := ntu.MapUnicastO2I(tb, slices.Collect(maps.Values(dkgParticipants)), r5uo)
	shards := make(map[sharing.ID]*dkls23.Shard[P, B, S])
	for id, party := range dkgParticipants {
		shards[id], err = party.Round6(r6ui[id])
		require.NoError(tb, err)
	}

	// transcripts match
	transcriptsBytes := make(map[sharing.ID][]byte)
	for id, ctx := range ctxs {
		var err error
		transcriptsBytes[id], err = ctx.Transcript().ExtractBytes("test", 32)
		require.NoError(tb, err)
	}
	transcriptBytesSlice := slices.Collect(maps.Values(transcriptsBytes))
	require.True(tb, sliceutils.All(transcriptBytesSlice, func(b []byte) bool { return bytes.Equal(transcriptBytesSlice[0], b) }))

	// public keys match
	publicKeys := slices.Collect(maps.Values(maputils.MapValues(shards, func(_ sharing.ID, s *dkls23.Shard[P, B, S]) P { return s.PublicKey().Value() })))
	for i := 1; i < accessStructure.Shareholders().Size(); i++ {
		require.True(tb, publicKeys[0].Equal(publicKeys[i]))
	}

	// secret shares match
	for th := accessStructure.Threshold(); th <= uint(accessStructure.Shareholders().Size()); th++ {
		for shardsSubset := range sliceutils.Combinations(slices.Collect(maps.Values(shards)), th) {
			feldmanScheme, err := feldman.NewScheme(curve.Generator(), accessStructure)
			require.NoError(tb, err)
			sharesSubset := sliceutils.Map(shardsSubset, func(s *dkls23.Shard[P, B, S]) *feldman.Share[S] {
				return s.Share()
			})
			recoveredSk, err := feldmanScheme.Reconstruct(sharesSubset...)
			require.NoError(tb, err)

			recoveredPk := curve.ScalarBaseMul(recoveredSk.Value())
			require.True(tb, recoveredPk.Equal(publicKeys[0]))
		}
	}

	return shards
}
