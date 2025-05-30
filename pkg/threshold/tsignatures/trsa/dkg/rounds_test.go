package dkg_test

import (
	crand "crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/rep23"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa/dkg"
)

const (
	threshold = 2
	total     = 3
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	var err error

	prng := crand.Reader

	identities, err := testutils.MakeDeterministicTestIdentities(total)
	require.NoError(t, err)

	protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, threshold)
	require.NoError(t, err)

	sessionId := []byte("test")
	tapes := testutils.MakeTranscripts("test", identities)

	participants := make([]*dkg.Participant, len(identities))
	for i, id := range identities {
		participants[i], err = dkg.NewParticipant(sessionId, id.(types.AuthKey), protocol, tapes[i], prng)
		require.NoError(t, err)
	}

	r1bo := make([]*dkg.Round1Broadcast, total)
	r1uo := make([]network.RoundMessages[types.ThresholdProtocol, *dkg.Round1P2P], total)
	for i, p := range participants {
		r1bo[i], r1uo[i], err = p.Round1()
		require.NoError(t, err)
	}

	r2bi, r2ui := testutils.MapO2I(t, participants, r1bo, r1uo)
	publicKeys := make([]*rsa.PublicKey, len(participants))
	shards := make([]*trsa.Shard, total)
	for i, p := range participants {
		publicKeys[i], shards[i], err = p.Round2(r2bi[i], r2ui[i])
		require.NoError(t, err)
	}

	t.Run("public keys match", func(t *testing.T) {
		t.Parallel()
		for i, s := range shards {
			require.Equal(t, uint64(trsa.RsaE), s.E)
			require.NotEqual(t, s.N1.Bytes(), s.N2.Bytes())
			require.Equal(t, publicKeys[i], s.PublicKey())
			if i > 0 {
				require.Equal(t, shards[i-1].N1.Bytes(), s.N1.Bytes())
				require.Equal(t, shards[i-1].N2.Bytes(), s.N2.Bytes())
				require.Equal(t, shards[i-1].PublicKey(), s.PublicKey())
			}
		}
	})

	t.Run("secret keys match public keys", func(t *testing.T) {
		t.Parallel()
		dealer := rep23.NewIntScheme()

		d1Shares := sliceutils.Map(shards, func(s *trsa.Shard) *rep23.IntShare { return s.D1Share })
		d1, err := dealer.Open(d1Shares...)
		require.NoError(t, err)
		baseBig, err := crand.Int(prng, shards[0].N1.Big())
		require.NoError(t, err)
		base := new(saferith.Nat).SetBig(baseBig, shards[0].N1.BitLen())
		check := new(saferith.Nat).ExpI(base, d1, shards[0].N1)
		check.Exp(check, new(saferith.Nat).SetUint64(trsa.RsaE), shards[0].N1)
		require.Equal(t, saferith.Choice(1), base.Eq(check))

		d2Shares := sliceutils.Map(shards, func(s *trsa.Shard) *rep23.IntShare { return s.D2Share })
		d2, err := dealer.Open(d2Shares...)
		require.NoError(t, err)
		baseBig, err = crand.Int(prng, shards[0].N2.Big())
		require.NoError(t, err)
		base = new(saferith.Nat).SetBig(baseBig, shards[0].N2.BitLen())
		check = new(saferith.Nat).ExpI(base, d2, shards[0].N2)
		check.Exp(check, new(saferith.Nat).SetUint64(trsa.RsaE), shards[0].N2)
		require.Equal(t, saferith.Choice(1), base.Eq(check))
	})
}
