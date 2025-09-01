package testutils

import (
	"bytes"
	crand "crypto/rand"
	"encoding/hex"
	"io"
	"maps"
	"slices"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/maputils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/dkls23/keygen/dkg"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"
)

func RunDKLs23DKG[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](tb testing.TB, curve ecdsa.Curve[P, B, S], accessStructure *shamir.AccessStructure) map[sharing.ID]*tecdsa.Shard[P, B, S] {
	tb.Helper()

	prng := crand.Reader
	var sessionId network.SID
	_, err := io.ReadFull(prng, sessionId[:])
	require.NoError(tb, err)

	tape := hagrid.NewTranscript(hex.EncodeToString(sessionId[:]))
	tapesMap := make(map[sharing.ID]transcripts.Transcript)
	dkgParticipantsMap := make(map[sharing.ID]*dkg.Participant[P, B, S])
	for id := range accessStructure.Shareholders().Iter() {
		tapesMap[id] = tape.Clone()
		dkgParticipantsMap[id], err = dkg.NewParticipant(sessionId, id, accessStructure, curve, tapesMap[id], prng)
		require.NoError(tb, err)
	}
	dkgParticipants := slices.Collect(maps.Values(dkgParticipantsMap))

	r1bo := make(map[sharing.ID]*dkg.Round1Broadcast[P, B, S])
	r1uo := make(map[sharing.ID]network.RoundMessages[*dkg.Round1P2P[P, B, S]])
	for _, party := range dkgParticipants {
		r1bo[party.SharingID()], r1uo[party.SharingID()], err = party.Round1()
		require.NoError(tb, err)
	}

	r2bi, r2ui := testutils.MapO2I(tb, dkgParticipants, r1bo, r1uo)
	r2bo := make(map[sharing.ID]*dkg.Round2Broadcast[P, B, S])
	r2uo := make(map[sharing.ID]network.RoundMessages[*dkg.Round2P2P[P, B, S]])
	for _, party := range dkgParticipants {
		r2bo[party.SharingID()], r2uo[party.SharingID()], err = party.Round2(r2bi[party.SharingID()], r2ui[party.SharingID()])
		require.NoError(tb, err)
	}

	r3bi, r3ui := testutils.MapO2I(tb, dkgParticipants, r2bo, r2uo)
	r3uo := make(map[sharing.ID]network.RoundMessages[*dkg.Round3P2P])
	for _, party := range dkgParticipants {
		r3uo[party.SharingID()], err = party.Round3(r3bi[party.SharingID()], r3ui[party.SharingID()])
		require.NoError(tb, err)
	}

	r4ui := testutils.MapUnicastO2I(tb, dkgParticipants, r3uo)
	r4uo := make(map[sharing.ID]network.RoundMessages[*dkg.Round4P2P])
	for _, party := range dkgParticipants {
		r4uo[party.SharingID()], err = party.Round4(r4ui[party.SharingID()])
		require.NoError(tb, err)
	}

	r5ui := testutils.MapUnicastO2I(tb, dkgParticipants, r4uo)
	r5uo := make(map[sharing.ID]network.RoundMessages[*dkg.Round5P2P])
	for _, party := range dkgParticipants {
		r5uo[party.SharingID()], err = party.Round5(r5ui[party.SharingID()])
		require.NoError(tb, err)
	}

	r6ui := testutils.MapUnicastO2I(tb, dkgParticipants, r5uo)
	shards := make(map[sharing.ID]*tecdsa.Shard[P, B, S])
	for _, party := range dkgParticipants {
		shards[party.SharingID()], err = party.Round6(r6ui[party.SharingID()])
		require.NoError(tb, err)
	}

	// transcripts match
	transcriptsBytes := make(map[sharing.ID][]byte)
	for id, tape := range tapesMap {
		var err error
		transcriptsBytes[id], err = tape.ExtractBytes("test", 32)
		require.NoError(tb, err)
	}
	transcriptBytesSlice := slices.Collect(maps.Values(transcriptsBytes))
	require.True(tb, sliceutils.All(transcriptBytesSlice, func(b []byte) bool { return bytes.Equal(transcriptBytesSlice[0], b) }))

	// public keys match
	publicKeys := slices.Collect(maps.Values(maputils.MapValues(shards, func(_ sharing.ID, s *tecdsa.Shard[P, B, S]) P { return s.PublicKey() })))
	for i := 1; i < accessStructure.Shareholders().Size(); i++ {
		require.True(tb, publicKeys[0].Equal(publicKeys[i]))
	}

	// secret shares match
	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](curve.ScalarStructure())
	for th := accessStructure.Threshold(); th <= uint(accessStructure.Shareholders().Size()); th++ {
		for shardsSubset := range sliceutils.Combinations(slices.Collect(maps.Values(shards)), th) {
			feldmanScheme, err := feldman.NewScheme(field, curve.Generator(), accessStructure.Threshold(), accessStructure.Shareholders())
			require.NoError(tb, err)
			sharesSubset := sliceutils.Map(shardsSubset, func(s *tecdsa.Shard[P, B, S]) *feldman.Share[S] {
				return s.Share()
			})
			recoveredSk, err := feldmanScheme.Reconstruct(sharesSubset...)
			recoveredPk := curve.ScalarBaseMul(recoveredSk.Value())
			require.True(tb, recoveredPk.Equal(publicKeys[0]))
		}
	}

	return shards
}
