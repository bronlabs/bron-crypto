package testutils

import (
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/chacha20"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	noninteractiveSigning "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/signing/noninteractive"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

func MakePreGenParticipants(t *testing.T, tau int, sid []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, shards []*dkls24.Shard, trans []transcripts.Transcript, prngs []io.Reader) []*noninteractiveSigning.PreGenParticipant {
	t.Helper()

	parties := make([]*noninteractiveSigning.PreGenParticipant, len(identities))
	seededPrng, err := chacha20.NewChachaPRNG(nil, nil)
	require.NoError(t, err)
	for i := range identities {
		var prng io.Reader
		if len(prngs) != 0 && prngs[i] != nil {
			prng = prngs[i]
		} else {
			prng = crand.Reader
		}
		var tran transcripts.Transcript
		if len(trans) != 0 && trans[i] != nil {
			tran = trans[i]
		}

		parties[i], err = noninteractiveSigning.NewPreGenParticipant(tau, identities[i].(integration.AuthKey), shards[i], sid, cohortConfig, tran, prng, seededPrng)
		require.NoError(t, err)
	}

	return parties
}

func RunPreGen(t *testing.T, parties []*noninteractiveSigning.PreGenParticipant) []*dkls24.PreSignatureBatch {
	t.Helper()
	var err error

	r1ob := make([]*noninteractiveSigning.Round1Broadcast, len(parties))
	r1ou := make([]map[types.IdentityHash]*noninteractiveSigning.Round1P2P, len(parties))
	for i := range parties {
		r1ob[i], r1ou[i], err = parties[i].Round1()
		require.NoError(t, err)
	}

	r2ib, r2iu := testutils.MapO2I(parties, r1ob, r1ou)
	r2ob := make([]*noninteractiveSigning.Round2Broadcast, len(parties))
	r2ou := make([]map[types.IdentityHash]*noninteractiveSigning.Round2P2P, len(parties))
	for i := range parties {
		r2ob[i], r2ou[i], err = parties[i].Round2(r2ib[i], r2iu[i])
		require.NoError(t, err)
	}

	r3ib, r3iu := testutils.MapO2I(parties, r2ob, r2ou)
	preSignatureBatches := make([]*dkls24.PreSignatureBatch, len(parties))
	for i := range parties {
		preSignatureBatches[i], err = parties[i].Round3(r3ib[i], r3iu[i])
		require.NoError(t, err)
	}

	return preSignatureBatches
}

func MakeNonInteractiveCosigners(t *testing.T, cohortConfig *integration.CohortConfig, sessionParticipants []integration.IdentityKey, shards []*dkls24.Shard, preSignatures []*dkls24.PreSignature) []*noninteractiveSigning.Cosigner {
	t.Helper()
	var err error

	cosigners := make([]*noninteractiveSigning.Cosigner, len(sessionParticipants))
	for i := range sessionParticipants {
		cosigners[i], err = noninteractiveSigning.NewCosigner(sessionParticipants[i].(integration.AuthKey), shards[i], cohortConfig, hashset.NewHashSet(sessionParticipants), preSignatures[i])
		require.NoError(t, err)
	}

	return cosigners
}
