package dkg_test

import (
	"maps"
	"slices"
	"testing"

	"github.com/bronlabs/errs-go/errs"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/trusteddealer"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21/keygen/dkg"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
)

// TestHappyPath drives the four-round aux-info protocol by hand over a trusted
// dealer's base shards and checks that every party ends with a consistent shard:
// the underlying key sharing is untouched, and the freshly generated Paillier /
// ring-Pedersen public material agrees across all parties while each secret key
// matches its own published public key.
func TestHappyPath(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	accessStructure, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	baseShards, shards := runRounds[*k256.Point, *k256.BaseFieldElement, *k256.Scalar](t, group, accessStructure)
	require.Len(t, shards, shareholders.Size())
	ids := shareholders.List()

	t.Run("base shard is preserved", func(t *testing.T) {
		t.Parallel()
		// The aux-info protocol only attaches Paillier/Pedersen material; it must
		// not alter the secret share, verification vector, or public key.
		for _, id := range ids {
			require.Equal(t, id, shards[id].Share().ID())
			require.True(t, baseShards[id].VerificationVector().Equal(shards[id].VerificationVector()))
			require.True(t, baseShards[id].PublicKeyValue().Equal(shards[id].PublicKeyValue()))
		}
	})

	t.Run("public key consistent across parties", func(t *testing.T) {
		t.Parallel()
		ref := shards[ids[0]].PublicKeyValue()
		for _, id := range ids {
			require.True(t, ref.Equal(shards[id].PublicKeyValue()))
		}
	})

	t.Run("aux info public keys agree across parties", func(t *testing.T) {
		t.Parallel()
		// Every party must hold the same map of per-party public Paillier and
		// ring-Pedersen keys; this is what binds the auxiliary info to the quorum.
		refPaillier := shards[ids[0]].AuxInfo().PaillierPublicKeys()
		refPedersen := shards[ids[0]].AuxInfo().RingPedersenPublicKeys()
		require.Len(t, refPaillier, len(ids))
		require.Len(t, refPedersen, len(ids))
		for _, id := range ids {
			pail := shards[id].AuxInfo().PaillierPublicKeys()
			ped := shards[id].AuxInfo().RingPedersenPublicKeys()
			for _, k := range ids {
				require.True(t, refPaillier[k].Equal(pail[k]))
				require.True(t, refPedersen[k].Equal(ped[k]))
			}
		}
	})

	t.Run("local secret keys match published public keys", func(t *testing.T) {
		t.Parallel()
		for _, id := range ids {
			info := shards[id].AuxInfo()
			require.True(t, info.PaillierSecretKey().Public().Equal(info.PaillierPublicKeys()[id]))
			require.True(t, info.RingPedersenSecretKey().Export().Equal(info.RingPedersenPublicKeys()[id]))
		}
	})

	t.Run("each party generated a distinct modulus", func(t *testing.T) {
		t.Parallel()
		ref := shards[ids[0]].AuxInfo().PaillierPublicKeys()
		for i := range ids {
			for j := i + 1; j < len(ids); j++ {
				require.False(t, ref[ids[i]].Equal(ref[ids[j]]))
			}
		}
	})
}

// runRounds executes the protocol round-by-round, mapping each round's outgoing
// messages to the next round's inputs through CBOR (de)serialisation, exactly as
// the wire would. It returns the dealer's base shards and the resulting shards.
func runRounds[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	tb testing.TB, group algebra.PrimeGroup[P, S], accessStructure accessstructures.Monotone,
) (map[sharing.ID]*mpc.BaseShard[P, S], map[sharing.ID]*cggmp21.Shard[P, B, S]) {
	tb.Helper()

	var err error
	prng := pcg.NewRandomised()
	quorum := accessStructure.Shareholders()
	ctxs := session_testutils.MakeRandomContexts(tb, quorum, prng)

	dealt, err := trusteddealer.Deal(group, accessStructure, prng)
	require.NoError(tb, err)

	baseShards := make(map[sharing.ID]*mpc.BaseShard[P, S])
	participants := make(map[sharing.ID]*dkg.Participant[P, B, S])
	for id := range quorum.Iter() {
		bs, ok := dealt.Get(id)
		require.True(tb, ok)
		baseShards[id] = bs
		participants[id], err = dkg.NewParticipant[P, B, S](ctxs[id], bs, pcg.NewRandomised())
		require.NoError(tb, err)
	}
	parts := slices.Collect(maps.Values(participants))

	// Round 1: broadcast the hash commitment V_i.
	r1bOut := make(map[sharing.ID]*dkg.Round1Broadcast[P, B, S])
	for id, p := range participants {
		r1bOut[id], err = p.Round1()
		require.NoError(tb, err)
	}

	// Round 2: broadcast the opening of V_i.
	r2bIn := ntu.MapBroadcastO2I(tb, parts, r1bOut)
	r2bOut := make(map[sharing.ID]*dkg.Round2Broadcast[P, B, S])
	for id, p := range participants {
		r2bOut[id], err = p.Round2(r2bIn[id])
		require.NoError(tb, err)
	}

	// Round 3: send the per-verifier fac proofs (and the shared blummod proof) by unicast.
	r3bIn := ntu.MapBroadcastO2I(tb, parts, r2bOut)
	r3uOut := make(map[sharing.ID]network.OutgoingUnicasts[*dkg.Round3P2P[P, B, S], *dkg.Participant[P, B, S]])
	for id, p := range participants {
		r3uOut[id], err = p.Round3(r3bIn[id])
		require.NoError(tb, err)
	}

	// Round 4: verify all proofs and assemble the shard.
	r4uIn := ntu.MapUnicastO2I(tb, parts, r3uOut)
	shards := make(map[sharing.ID]*cggmp21.Shard[P, B, S])
	for id, p := range participants {
		shards[id], err = p.Round4(r4uIn[id])
		require.NoError(tb, err)
	}
	return baseShards, shards
}

// TestNewParticipantValidation covers the constructor's input checks. None of
// these reach the (expensive) key generation in Round1.
func TestNewParticipantValidation(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	as, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)
	prng := pcg.NewRandomised()
	ctxs := session_testutils.MakeRandomContexts(t, as.Shareholders(), prng)
	dealt, err := trusteddealer.Deal(group, as, prng)
	require.NoError(t, err)
	// Snapshot the order once: List() is hashset-backed and non-deterministic,
	// so id and otherID below must come from the same slice to stay distinct.
	ids := shareholders.List()
	id := ids[0]
	bs, ok := dealt.Get(id)
	require.True(t, ok)

	t.Run("nil ctx", func(t *testing.T) {
		t.Parallel()
		_, err := dkg.NewParticipant[*k256.Point, *k256.BaseFieldElement, *k256.Scalar](nil, bs, prng)
		require.True(t, errs.Is(err, cggmp21.ErrNil))
	})

	t.Run("nil base shard", func(t *testing.T) {
		t.Parallel()
		_, err := dkg.NewParticipant[*k256.Point, *k256.BaseFieldElement, *k256.Scalar](ctxs[id], nil, prng)
		require.True(t, errs.Is(err, cggmp21.ErrNil))
	})

	t.Run("nil prng", func(t *testing.T) {
		t.Parallel()
		_, err := dkg.NewParticipant[*k256.Point, *k256.BaseFieldElement, *k256.Scalar](ctxs[id], bs, nil)
		require.True(t, errs.Is(err, cggmp21.ErrNil))
	})

	t.Run("holder id not matching the base shard", func(t *testing.T) {
		t.Parallel()
		otherID := ids[1] // distinct from id (same snapshot)
		_, err := dkg.NewParticipant[*k256.Point, *k256.BaseFieldElement, *k256.Scalar](ctxs[otherID], bs, prng)
		require.True(t, errs.Is(err, cggmp21.ErrValidationFailed))
	})

	t.Run("quorum not matching the base shard shareholders", func(t *testing.T) {
		t.Parallel()
		// A larger quorum {1,2,3,4} still contains id, so the holder check passes
		// and the quorum-mismatch check ({1,2,3,4} != base shard's {1,2,3}) is the
		// one that fires — regardless of which id was picked from the set.
		otherQuorum := sharing.NewOrdinalShareholderSet(4)
		otherAS, err := threshold.NewThresholdAccessStructure(2, otherQuorum)
		require.NoError(t, err)
		otherCtxs := session_testutils.MakeRandomContexts(t, otherAS.Shareholders(), pcg.NewRandomised())
		_, err = dkg.NewParticipant[*k256.Point, *k256.BaseFieldElement, *k256.Scalar](otherCtxs[id], bs, prng)
		require.True(t, errs.Is(err, cggmp21.ErrValidationFailed))
	})
}

// TestRoundOrderEnforcement checks that each round refuses to run out of turn.
func TestRoundOrderEnforcement(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	as, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)
	id := shareholders.List()[0]
	dealt, err := trusteddealer.Deal(group, as, pcg.NewRandomised())
	require.NoError(t, err)
	bs, ok := dealt.Get(id)
	require.True(t, ok)

	// Each call gets its own fresh context, since a successful NewParticipant
	// mutates the session transcript.
	newParticipant := func() *dkg.Participant[*k256.Point, *k256.BaseFieldElement, *k256.Scalar] {
		ctxs := session_testutils.MakeRandomContexts(t, as.Shareholders(), pcg.NewRandomised())
		p, err := dkg.NewParticipant[*k256.Point, *k256.BaseFieldElement, *k256.Scalar](ctxs[id], bs, pcg.NewRandomised())
		require.NoError(t, err)
		return p
	}

	t.Run("round 2 before round 1", func(t *testing.T) {
		t.Parallel()
		_, err := newParticipant().Round2(nil)
		require.True(t, errs.Is(err, cggmp21.ErrRound))
	})

	t.Run("round 3 before round 1", func(t *testing.T) {
		t.Parallel()
		_, err := newParticipant().Round3(nil)
		require.True(t, errs.Is(err, cggmp21.ErrRound))
	})

	t.Run("round 4 before round 1", func(t *testing.T) {
		t.Parallel()
		_, err := newParticipant().Round4(nil)
		require.True(t, errs.Is(err, cggmp21.ErrRound))
	})
}
