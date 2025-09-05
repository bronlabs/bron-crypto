package testutils

import (
	"bytes"
	crand "crypto/rand"
	"encoding/hex"
	"hash"
	"io"
	"maps"
	"slices"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/dkls23/signing/interactive/sign_softspoken"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"
)

func RunDKLs23SignSoftspokenOT[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](tb testing.TB, shards map[sharing.ID]*tecdsa.Shard[P, B, S], quorum ds.Set[sharing.ID], message []byte, hashFunc func() hash.Hash) *ecdsa.Signature[S] {
	tb.Helper()

	prng := crand.Reader
	var sessionId network.SID
	_, err := io.ReadFull(prng, sessionId[:])
	require.NoError(tb, err)
	tape := hagrid.NewTranscript(hex.EncodeToString(sessionId[:]))
	pk := slices.Collect(maps.Values(shards))[0].PublicKey()
	curve := algebra.StructureMustBeAs[ecdsa.Curve[P, B, S]](pk.Value().Structure())
	ecdsaSuite, err := ecdsa.NewSuite(curve, hashFunc)
	require.NoError(tb, err)

	tapesMap := make(map[sharing.ID]transcripts.Transcript)
	consignersMap := make(map[sharing.ID]*sign_softspoken.Cosigner[P, B, S])
	for id := range quorum.Iter() {
		shard, ok := shards[id]
		require.True(tb, ok)
		tapesMap[id] = tape.Clone()
		consignersMap[id], err = sign_softspoken.NewCosigner(sessionId, quorum, ecdsaSuite, shard, prng, tapesMap[id])
		require.NoError(tb, err)
	}
	cosigners := slices.Collect(maps.Values(consignersMap))

	r1bo := make(map[sharing.ID]*sign_softspoken.Round1Broadcast)
	r1uo := make(map[sharing.ID]ds.Map[sharing.ID, *sign_softspoken.Round1P2P])
	for _, cosigner := range cosigners {
		r1bo[cosigner.SharingID()], r1uo[cosigner.SharingID()], err = cosigner.Round1()
		require.NoError(tb, err)
	}

	r2bi, r2ui := testutils.MapO2I(tb, cosigners, r1bo, r1uo)
	r2bo := make(map[sharing.ID]*sign_softspoken.Round2Broadcast[P, B, S])
	r2uo := make(map[sharing.ID]ds.Map[sharing.ID, *sign_softspoken.Round2P2P[P, B, S]])
	for _, cosigner := range cosigners {
		r2bo[cosigner.SharingID()], r2uo[cosigner.SharingID()], err = cosigner.Round2(r2bi[cosigner.SharingID()], r2ui[cosigner.SharingID()])
		require.NoError(tb, err)
	}

	r3bi, r3ui := testutils.MapO2I(tb, cosigners, r2bo, r2uo)
	partialSignatures := make(map[sharing.ID]*dkls23.PartialSignature[P, B, S])
	for _, cosigner := range cosigners {
		partialSignatures[cosigner.SharingID()], err = cosigner.Round3(r3bi[cosigner.SharingID()], r3ui[cosigner.SharingID()], message)
		require.NoError(tb, err)
	}

	signature, err := dkls23.Aggregate(ecdsaSuite, pk, message, slices.Collect(maps.Values(partialSignatures))...)
	require.NoError(tb, err)

	// transcripts match
	transcriptsBytes := make(map[sharing.ID][]byte)
	for id, tape := range tapesMap {
		var err error
		transcriptsBytes[id], err = tape.ExtractBytes("test", 32)
		require.NoError(tb, err)
	}
	transcriptBytesSlice := slices.Collect(maps.Values(transcriptsBytes))
	require.True(tb, sliceutils.All(transcriptBytesSlice, func(b []byte) bool { return bytes.Equal(transcriptBytesSlice[0], b) }))

	return signature
}
