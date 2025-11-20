package echo

import (
	"math/rand/v2"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/stretchr/testify/require"
)

func TestHappyPath(t *testing.T) {
	ids := sharing.NewOrdinalShareholderSet(3)
	parties := []*Participant[uint64]{}
	for id := range ids.Iter() {
		p, err := NewParticipant[uint64](id, ids)
		require.NoError(t, err)
		parties = append(parties, p)
	}

	var err error
	r1 := make(map[sharing.ID]network.OutgoingUnicasts[*Round1P2P])
	for _, p := range parties {
		r1[p.SharingID()], err = p.Round1(rand.Uint64())
		require.NoError(t, err)
	}
	r2In := testutils.MapUnicastO2I(t, parties, r1)

	r2 := make(map[sharing.ID]network.OutgoingUnicasts[*Round2P2P])
	for _, p := range parties {
		r2[p.SharingID()], err = p.Round2(r2In[p.SharingID()])
		require.NoError(t, err)
	}
	r3In := testutils.MapUnicastO2I(t, parties, r2)

	for _, p := range parties {
		_, err := p.Round3(r3In[p.SharingID()])
		require.NoError(t, err)
	}
}
