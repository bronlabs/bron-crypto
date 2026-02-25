package echo_test

import (
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/echo"
	"github.com/bronlabs/bron-crypto/pkg/network/testutils"
)

func TestHappyPath(t *testing.T) {
	t.Parallel()
	ids := sharing.NewOrdinalShareholderSet(3)
	parties := []*echo.Participant[uint64]{}
	for id := range ids.Iter() {
		p, err := echo.NewParticipant[uint64](id, ids)
		require.NoError(t, err)
		parties = append(parties, p)
	}

	var err error
	r1 := make(map[sharing.ID]network.OutgoingUnicasts[*echo.Round1P2P])
	for _, p := range parties {
		r1[p.SharingID()], err = p.Round1(rand.Uint64())
		require.NoError(t, err)
	}
	r2In := ntu.MapUnicastO2I(t, parties, r1)

	r2 := make(map[sharing.ID]network.OutgoingUnicasts[*echo.Round2P2P])
	for _, p := range parties {
		r2[p.SharingID()], err = p.Round2(r2In[p.SharingID()])
		require.NoError(t, err)
	}
	r3In := ntu.MapUnicastO2I(t, parties, r2)

	for _, p := range parties {
		_, err := p.Round3(r3In[p.SharingID()])
		require.NoError(t, err)
	}
}
