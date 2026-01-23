package testutils

import (
	crand "crypto/rand"
	"encoding/hex"
	"io"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/maputils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/lindell17"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/lindell17/keygen/dkg"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

const paillierKeyLen = 1536

// RunLindell17DKG runs a complete Lindell17 DKG protocol and returns the resulting shards.
// It verifies that all participants produce consistent outputs.
func RunLindell17DKG[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	tb testing.TB,
	curve ecdsa.Curve[P, B, S],
	accessStructure *sharing.ThresholdAccessStructure,
) map[sharing.ID]*lindell17.Shard[P, B, S] {
	tb.Helper()

	prng := crand.Reader
	var sessionID network.SID
	_, err := io.ReadFull(prng, sessionID[:])
	require.NoError(tb, err)

	tape := hagrid.NewTranscript(hex.EncodeToString(sessionID[:]))

	// Create initial shards from Feldman DKG (or use a dealer)
	feldmanScheme, err := feldman.NewScheme(curve.Generator(), accessStructure.Threshold(), accessStructure.Shareholders())
	require.NoError(tb, err)

	feldmanOutput, _, err := feldmanScheme.DealRandom(prng)
	require.NoError(tb, err)

	// Create base tecdsa shards
	baseShards := make(map[sharing.ID]*tecdsa.Shard[P, B, S])
	for id, share := range feldmanOutput.Shares().Iter() {
		baseShard, err := tecdsa.NewShard(share, feldmanOutput.VerificationMaterial(), accessStructure)
		require.NoError(tb, err)
		baseShards[id] = baseShard
	}

	// Create DKG participants
	participants := make(map[sharing.ID]*dkg.Participant[P, B, S])
	for id, shard := range baseShards {
		participants[id], err = dkg.NewParticipant(
			sessionID,
			shard,
			paillierKeyLen,
			curve,
			prng,
			fiatshamir.Name,
			tape.Clone(),
		)
		require.NoError(tb, err)
	}

	participantsList := slices.Collect(maps.Values(participants))

	// Round 1: Broadcast commitments
	r1bo := make(map[sharing.ID]*dkg.Round1Broadcast)
	for _, party := range participantsList {
		r1bo[party.SharingID()], err = party.Round1()
		require.NoError(tb, err)
	}

	// Round 2: Broadcast openings and DLog proofs
	r2bi := ntu.MapBroadcastO2I(tb, participantsList, r1bo)
	r2bo := make(map[sharing.ID]*dkg.Round2Broadcast[P, B, S])
	for _, party := range participantsList {
		r2bo[party.SharingID()], err = party.Round2(r2bi[party.SharingID()])
		require.NoError(tb, err)
	}

	// Round 3: Broadcast Paillier keys and encrypted shares
	r3bi := ntu.MapBroadcastO2I(tb, participantsList, r2bo)
	r3bo := make(map[sharing.ID]*dkg.Round3Broadcast)
	for _, party := range participantsList {
		r3bo[party.SharingID()], err = party.Round3(r3bi[party.SharingID()])
		require.NoError(tb, err)
	}

	// Round 4: P2P for LP and LPDL proofs
	r4bi := ntu.MapBroadcastO2I(tb, participantsList, r3bo)
	r4uo := make(map[sharing.ID]network.OutgoingUnicasts[*dkg.Round4P2P])
	for _, party := range participantsList {
		r4uo[party.SharingID()], err = party.Round4(r4bi[party.SharingID()])
		require.NoError(tb, err)
	}

	// Round 5: P2P continuation
	r5ui := ntu.MapUnicastO2I(tb, participantsList, r4uo)
	r5uo := make(map[sharing.ID]network.OutgoingUnicasts[*dkg.Round5P2P])
	for _, party := range participantsList {
		r5uo[party.SharingID()], err = party.Round5(r5ui[party.SharingID()])
		require.NoError(tb, err)
	}

	// Round 6: P2P continuation
	r6ui := ntu.MapUnicastO2I(tb, participantsList, r5uo)
	r6uo := make(map[sharing.ID]network.OutgoingUnicasts[*dkg.Round6P2P])
	for _, party := range participantsList {
		r6uo[party.SharingID()], err = party.Round6(r6ui[party.SharingID()])
		require.NoError(tb, err)
	}

	// Round 7: P2P continuation
	r7ui := ntu.MapUnicastO2I(tb, participantsList, r6uo)
	r7uo := make(map[sharing.ID]network.OutgoingUnicasts[*dkg.Round7P2P[P, B, S]])
	for _, party := range participantsList {
		r7uo[party.SharingID()], err = party.Round7(r7ui[party.SharingID()])
		require.NoError(tb, err)
	}

	// Round 8: Final round - get shards
	r8ui := ntu.MapUnicastO2I(tb, participantsList, r7uo)
	shards := make(map[sharing.ID]*lindell17.Shard[P, B, S])
	for _, party := range participantsList {
		shards[party.SharingID()], err = party.Round8(r8ui[party.SharingID()])
		require.NoError(tb, err)
	}

	// Verify consistency

	// 1. Public keys should match across all shards
	publicKeys := slices.Collect(maps.Values(maputils.MapValues(shards, func(_ sharing.ID, s *lindell17.Shard[P, B, S]) P {
		return s.PublicKey().Value()
	})))
	for i := 1; i < accessStructure.Shareholders().Size(); i++ {
		require.True(tb, publicKeys[0].Equal(publicKeys[i]), "All participants should derive the same public key")
	}

	// 2. Secret shares should reconstruct to the same secret for any threshold-sized subset
	for th := accessStructure.Threshold(); th <= uint(accessStructure.Shareholders().Size()); th++ {
		for shardsSubset := range sliceutils.Combinations(slices.Collect(maps.Values(shards)), th) {
			sharesSubset := sliceutils.Map(shardsSubset, func(s *lindell17.Shard[P, B, S]) *feldman.Share[S] {
				return s.Share()
			})
			recoveredSk, err := feldmanScheme.Reconstruct(sharesSubset...)
			require.NoError(tb, err)
			recoveredPk := curve.ScalarBaseMul(recoveredSk.Value())
			require.True(tb, recoveredPk.Equal(publicKeys[0]),
				"Reconstructed secret should match the public key")
		}
	}

	return shards
}
